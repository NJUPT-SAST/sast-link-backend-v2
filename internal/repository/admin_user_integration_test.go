package repository_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// assertPairRevokedAt checks a single token pair. The shared assertFamilyRevokedAt
// expects two pairs per family, which is the rotation scenario; these tests seed
// one pair each.
func assertPairRevokedAt(t *testing.T, database *gorm.DB, familyID string, want time.Time) {
	t.Helper()
	var access model.OAuthAccessToken
	if err := database.Where("family_id = ?", familyID).First(&access).Error; err != nil {
		t.Fatalf("read access token for %q: %v", familyID, err)
	}
	var refresh model.OAuthRefreshToken
	if err := database.Where("family_id = ?", familyID).First(&refresh).Error; err != nil {
		t.Fatalf("read refresh token for %q: %v", familyID, err)
	}
	if access.RevokedAt == nil || !access.RevokedAt.Equal(want) {
		t.Fatalf("access token revoked_at = %v, want %v", access.RevokedAt, want)
	}
	if refresh.RevokedAt == nil || !refresh.RevokedAt.Equal(want) {
		t.Fatalf("refresh token revoked_at = %v, want %v", refresh.RevokedAt, want)
	}
}

// adminSeed creates a user with explicit role, state and display name so the list
// filters have something to discriminate on.
func adminSeed(
	t *testing.T,
	database *gorm.DB,
	loginEmail, name string,
	role model.UserRole,
	state model.UserState,
	department *model.Department,
) *model.User {
	t.Helper()
	users := repository.NewUser(database)
	user := testUser(loginEmail)
	user.Name = name
	user.Role = role
	user.State = state
	profile := &model.Profile{Department: department}
	if err := users.CreateWithProfile(context.Background(), user, profile); err != nil {
		t.Fatalf("seed %q: %v", loginEmail, err)
	}
	return user
}

func TestListAdminUsersFiltersAndPages(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	software := model.DepartmentSoftware
	media := model.DepartmentMedia

	adminSeed(t, database, "b001@njupt.edu.cn", "张三", model.UserRoleMember, model.UserStateOnSAST, &software)
	adminSeed(t, database, "b002@njupt.edu.cn", "李四", model.UserRoleLecturer, model.UserStateOnSAST, &media)
	adminSeed(t, database, "b003@njupt.edu.cn", "王五", model.UserRoleFreshman, model.UserStateNJUPTer, nil)
	deleted := adminSeed(t, database, "b004@njupt.edu.cn", "赵六",
		model.UserRoleMember, model.UserStateDeleted, &software)

	t.Run("unfiltered includes soft-deleted", func(t *testing.T) {
		rows, total, err := users.ListAdminUsers(context.Background(),
			repository.AdminUserFilter{Limit: 10})
		if err != nil {
			t.Fatalf("ListAdminUsers: %v", err)
		}
		if total != 4 || len(rows) != 4 {
			t.Fatalf("total/rows = %d/%d, want 4/4", total, len(rows))
		}
		var found bool
		for _, row := range rows {
			if row.ID == deleted.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("the soft-deleted account is missing; the console could not restore it")
		}
	})

	t.Run("by role", func(t *testing.T) {
		role := model.UserRoleLecturer
		rows, total, err := users.ListAdminUsers(context.Background(),
			repository.AdminUserFilter{Role: &role, Limit: 10})
		if err != nil {
			t.Fatalf("ListAdminUsers: %v", err)
		}
		if total != 1 || len(rows) != 1 || rows[0].Name != "李四" {
			t.Fatalf("rows = %+v (total %d), want just the lecturer", rows, total)
		}
	})

	t.Run("by state", func(t *testing.T) {
		state := model.UserStateOnSAST
		_, total, err := users.ListAdminUsers(context.Background(),
			repository.AdminUserFilter{State: &state, Limit: 10})
		if err != nil {
			t.Fatalf("ListAdminUsers: %v", err)
		}
		if total != 2 {
			t.Fatalf("total = %d, want 2 on_sast users", total)
		}
	})

	t.Run("by department across the join", func(t *testing.T) {
		rows, total, err := users.ListAdminUsers(context.Background(),
			repository.AdminUserFilter{Department: &software, Limit: 10})
		if err != nil {
			t.Fatalf("ListAdminUsers: %v", err)
		}
		if total != 2 || len(rows) != 2 {
			t.Fatalf("total/rows = %d/%d, want 2/2 in software", total, len(rows))
		}
		for _, row := range rows {
			if row.Department == nil || *row.Department != software {
				t.Fatalf("row %d department = %v, want software", row.ID, row.Department)
			}
		}
	})

	t.Run("a user with no department is still listed", func(t *testing.T) {
		rows, _, err := users.ListAdminUsers(context.Background(),
			repository.AdminUserFilter{Keyword: "王五", Limit: 10})
		if err != nil {
			t.Fatalf("ListAdminUsers: %v", err)
		}
		if len(rows) != 1 || rows[0].Department != nil {
			t.Fatalf("rows = %+v, want one row with a null department", rows)
		}
	})

	t.Run("keyword matches name, student id and email", func(t *testing.T) {
		for _, keyword := range []string{"张", "b001", "B b001"[2:]} {
			rows, _, err := users.ListAdminUsers(context.Background(),
				repository.AdminUserFilter{Keyword: keyword, Limit: 10})
			if err != nil {
				t.Fatalf("ListAdminUsers(%q): %v", keyword, err)
			}
			if len(rows) == 0 {
				t.Fatalf("keyword %q matched nothing", keyword)
			}
		}
	})

	t.Run("keyword is case insensitive", func(t *testing.T) {
		rows, _, err := users.ListAdminUsers(context.Background(),
			repository.AdminUserFilter{Keyword: "B001@NJUPT", Limit: 10})
		if err != nil {
			t.Fatalf("ListAdminUsers: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("rows = %d, want the ILIKE match to ignore case", len(rows))
		}
	})

	t.Run("paging does not overlap or skip", func(t *testing.T) {
		seen := make(map[int64]bool)
		for offset := 0; offset < 4; offset += 2 {
			rows, total, err := users.ListAdminUsers(context.Background(),
				repository.AdminUserFilter{Limit: 2, Offset: offset})
			if err != nil {
				t.Fatalf("ListAdminUsers(offset %d): %v", offset, err)
			}
			if total != 4 {
				t.Fatalf("total = %d on offset %d, want 4 regardless of the window", total, offset)
			}
			if len(rows) != 2 {
				t.Fatalf("rows = %d on offset %d, want 2", len(rows), offset)
			}
			for _, row := range rows {
				if seen[row.ID] {
					t.Fatalf("user %d appeared on two pages", row.ID)
				}
				seen[row.ID] = true
			}
		}
		if len(seen) != 4 {
			t.Fatalf("saw %d distinct users across the pages, want 4", len(seen))
		}
	})

	t.Run("an offset past the end is an empty page, not an error", func(t *testing.T) {
		rows, total, err := users.ListAdminUsers(context.Background(),
			repository.AdminUserFilter{Limit: 10, Offset: 100})
		if err != nil {
			t.Fatalf("ListAdminUsers: %v", err)
		}
		if total != 4 || len(rows) != 0 {
			t.Fatalf("total/rows = %d/%d, want 4/0", total, len(rows))
		}
	})

	t.Run("a non-positive limit is rejected", func(t *testing.T) {
		if _, _, err := users.ListAdminUsers(context.Background(),
			repository.AdminUserFilter{Limit: 0}); !errors.Is(err, repository.ErrInvalidArgument) {
			t.Fatalf("error = %v, want ErrInvalidArgument", err)
		}
	})
}

// A keyword of "%" or "_" is a literal search term, not a wildcard. Without
// escaping, "%" would match every account and the search would silently mean
// something other than what was typed.
func TestListAdminUsersEscapesKeywordWildcards(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	adminSeed(t, database, "b100@njupt.edu.cn", "100%纯棉", model.UserRoleMember, model.UserStateOnSAST, nil)
	adminSeed(t, database, "b101@njupt.edu.cn", "普通名字", model.UserRoleMember, model.UserStateOnSAST, nil)

	for _, testCase := range []struct {
		keyword  string
		wantRows int
	}{
		// A bare wildcard must match only the row that literally contains it.
		{"%", 1},
		{"100%", 1},
		{"_", 0},
		// A backslash must not escape the character after it into a wildcard.
		{`\`, 0},
	} {
		t.Run(testCase.keyword, func(t *testing.T) {
			rows, _, err := users.ListAdminUsers(context.Background(),
				repository.AdminUserFilter{Keyword: testCase.keyword, Limit: 10})
			if err != nil {
				t.Fatalf("ListAdminUsers(%q): %v", testCase.keyword, err)
			}
			if len(rows) != testCase.wantRows {
				t.Fatalf("keyword %q matched %d rows, want %d",
					testCase.keyword, len(rows), testCase.wantRows)
			}
		})
	}
}

// A role change must increment token_version and revoke every live token in the
// same transaction, or a demoted account keeps refresh tokens able to mint new
// access tokens.
func TestUpdateAdminUserRevokesSessionsAtomically(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	tokens := repository.NewToken(database)
	client := createOAuthClient(t, database)
	user := adminSeed(t, database, "b200@njupt.edu.cn", "被降权",
		model.UserRoleAdmin, model.UserStateOnSAST, nil)
	// A second admin so the last-admin guard does not block the demotion.
	adminSeed(t, database, "b201@njupt.edu.cn", "另一管理员",
		model.UserRoleAdmin, model.UserStateOnSAST, nil)

	familyID := "family-demote"
	createTokenPair(t, tokens, "demote", familyID, 0, client.ID, user.ID)
	revokedAt := time.Now().UTC().Truncate(time.Microsecond)

	role := model.UserRoleMember
	entries, err := users.UpdateAdminUser(context.Background(), user.ID,
		repository.AdminUserUpdate{Role: &role}, revokedAt)
	if err != nil {
		t.Fatalf("UpdateAdminUser: %v", err)
	}
	if len(entries) != 1 || entries[0].TokenID != "demote-access" {
		t.Fatalf("entries = %+v, want the live access token returned for blacklisting", entries)
	}
	assertPairRevokedAt(t, database, familyID, revokedAt)

	var reloaded model.User
	if err := database.First(&reloaded, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if reloaded.Role != model.UserRoleMember {
		t.Fatalf("role = %q, want member", reloaded.Role)
	}
	if reloaded.TokenVersion != user.TokenVersion+1 {
		t.Fatalf("token_version = %d, want %d", reloaded.TokenVersion, user.TokenVersion+1)
	}
}

// An edit that does not touch the role leaves the sessions alone: re-authenticating
// every user whose phone number was corrected would be a denial of service.
func TestUpdateAdminUserKeepsSessionsWhenRoleUnchanged(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	tokens := repository.NewToken(database)
	client := createOAuthClient(t, database)
	user := adminSeed(t, database, "b210@njupt.edu.cn", "改资料",
		model.UserRoleMember, model.UserStateOnSAST, nil)
	familyID := "family-keep"
	createTokenPair(t, tokens, "keep", familyID, 0, client.ID, user.ID)

	name := "新名字"
	entries, err := users.UpdateAdminUser(context.Background(), user.ID,
		repository.AdminUserUpdate{Name: &name}, time.Now().UTC())
	if err != nil {
		t.Fatalf("UpdateAdminUser: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %+v, want none for a profile-only edit", entries)
	}
	assertFamilyUnrevoked(t, database, familyID)

	var reloaded model.User
	if err := database.First(&reloaded, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if reloaded.TokenVersion != user.TokenVersion {
		t.Fatalf("token_version = %d, want it untouched at %d",
			reloaded.TokenVersion, user.TokenVersion)
	}
}

// The V001 trigger recomputes email_type from the domain whenever login_email is in
// the UPDATE column list, so an administrative address change must land with a
// consistent type.
func TestUpdateAdminUserLetsTriggerRecomputeEmailType(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	user := adminSeed(t, database, "b220@njupt.edu.cn", "换邮箱",
		model.UserRoleMember, model.UserStateOnSAST, nil)

	email := "moved@sast.fun"
	emailType := model.EmailTypeSAST
	if _, err := users.UpdateAdminUser(context.Background(), user.ID,
		repository.AdminUserUpdate{LoginEmail: &email, EmailType: &emailType},
		time.Now().UTC()); err != nil {
		t.Fatalf("UpdateAdminUser: %v", err)
	}
	var reloaded model.User
	if err := database.First(&reloaded, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if reloaded.LoginEmail != email || reloaded.EmailType != model.EmailTypeSAST {
		t.Fatalf("email/type = %q/%q, want %q/sast_email",
			reloaded.LoginEmail, reloaded.EmailType, email)
	}
}

// An unknown domain must be refused by the trigger rather than stored, which is why
// the service validates the domain before ever reaching here.
func TestUpdateAdminUserRejectsForeignEmailDomain(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	user := adminSeed(t, database, "b230@njupt.edu.cn", "外域邮箱",
		model.UserRoleMember, model.UserStateOnSAST, nil)

	email := "someone@gmail.com"
	if _, err := users.UpdateAdminUser(context.Background(), user.ID,
		repository.AdminUserUpdate{LoginEmail: &email},
		time.Now().UTC()); err == nil {
		t.Fatal("UpdateAdminUser accepted a foreign domain; the trigger should refuse it")
	}
}

// A closed account is not editable through this path: reopening it is restore's
// job, and the predicate is what keeps that true even if a caller skips the
// service's check.
func TestUpdateAdminUserSkipsDeletedAccounts(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	user := adminSeed(t, database, "b240@njupt.edu.cn", "已注销",
		model.UserRoleMember, model.UserStateDeleted, nil)

	name := "改不动"
	_, err := users.UpdateAdminUser(context.Background(), user.ID,
		repository.AdminUserUpdate{Name: &name}, time.Now().UTC())
	// The row exists and the caller may see it in the console, so the closed state is
	// a conflict to report rather than a missing record. Reporting ErrNotFound here
	// would render as a 404 on a user the list just showed, and it would disagree with
	// the delete path, which classifies the same condition.
	if !errors.Is(err, repository.ErrStateConflict) {
		t.Fatalf("error = %v, want ErrStateConflict for a closed account", err)
	}
}

// A genuinely absent row is still a 404, so the two conditions stay distinguishable.
func TestUpdateAdminUserReportsAMissingRowAsNotFound(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)

	name := "无此人"
	_, err := users.UpdateAdminUser(context.Background(), 999999999,
		repository.AdminUserUpdate{Name: &name}, time.Now().UTC())
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestUpdateAdminUserRejectsEmptyUpdate(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)

	_, err := users.UpdateAdminUser(context.Background(), 1,
		repository.AdminUserUpdate{}, time.Now().UTC())
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("error = %v, want ErrInvalidArgument", err)
	}
}

func TestSoftDeleteAndRevokeSessions(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	tokens := repository.NewToken(database)
	client := createOAuthClient(t, database)
	user := adminSeed(t, database, "b300@njupt.edu.cn", "待注销",
		model.UserRoleMember, model.UserStateOnSAST, nil)
	familyID := "family-delete"
	createTokenPair(t, tokens, "delete", familyID, 0, client.ID, user.ID)
	revokedAt := time.Now().UTC().Truncate(time.Microsecond)

	entries, err := users.SoftDeleteAndRevokeSessions(context.Background(), user.ID, revokedAt)
	if err != nil {
		t.Fatalf("SoftDeleteAndRevokeSessions: %v", err)
	}
	if len(entries) != 1 || entries[0].TokenID != "delete-access" {
		t.Fatalf("entries = %+v, want the live access token", entries)
	}
	assertPairRevokedAt(t, database, familyID, revokedAt)

	var reloaded model.User
	if err := database.First(&reloaded, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if reloaded.State != model.UserStateDeleted {
		t.Fatalf("state = %q, want is_deleted", reloaded.State)
	}
	if reloaded.TokenVersion != user.TokenVersion+1 {
		t.Fatalf("token_version = %d, want %d", reloaded.TokenVersion, user.TokenVersion+1)
	}

	t.Run("closing it twice is a state conflict", func(t *testing.T) {
		_, err := users.SoftDeleteAndRevokeSessions(context.Background(), user.ID, revokedAt)
		if !errors.Is(err, repository.ErrStateConflict) {
			t.Fatalf("error = %v, want ErrStateConflict", err)
		}
	})
}

func TestSoftDeleteReportsMissingUser(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)

	_, err := users.SoftDeleteAndRevokeSessions(context.Background(), 999999, time.Now().UTC())
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

// Restore returns the account to njupter and does not resurrect the tokens that
// were revoked when it closed; the owner signs in again.
func TestRestoreUser(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	tokens := repository.NewToken(database)
	client := createOAuthClient(t, database)
	user := adminSeed(t, database, "b400@njupt.edu.cn", "待恢复",
		model.UserRoleMember, model.UserStateOnSAST, nil)
	familyID := "family-restore"
	createTokenPair(t, tokens, "restore", familyID, 0, client.ID, user.ID)
	revokedAt := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := users.SoftDeleteAndRevokeSessions(context.Background(), user.ID, revokedAt); err != nil {
		t.Fatalf("soft delete: %v", err)
	}

	if err := users.RestoreUser(context.Background(), user.ID); err != nil {
		t.Fatalf("RestoreUser: %v", err)
	}
	var reloaded model.User
	if err := database.First(&reloaded, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	// The previous state is not remembered: an on_sast member comes back as a njupter
	// and an administrator re-promotes them.
	if reloaded.State != model.UserStateNJUPTer {
		t.Fatalf("state = %q, want njupter", reloaded.State)
	}
	assertPairRevokedAt(t, database, familyID, revokedAt)

	t.Run("restoring a live account is a state conflict", func(t *testing.T) {
		err := users.RestoreUser(context.Background(), user.ID)
		if !errors.Is(err, repository.ErrStateConflict) {
			t.Fatalf("error = %v, want ErrStateConflict", err)
		}
	})

	t.Run("restoring a missing account is not found", func(t *testing.T) {
		err := users.RestoreUser(context.Background(), 999999)
		if !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("error = %v, want ErrNotFound", err)
		}
	})
}

// email_type is derived from login_email by a V001 trigger that only fires when
// login_email is in the SET list. Accepting email_type on its own would store a type
// contradicting the address, and nothing downstream recomputes it.
func TestUpdateAdminUserRefusesEmailTypeWithoutAddress(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	user := adminSeed(t, database, "b2404@njupt.edu.cn", "学生邮箱",
		model.UserRoleMember, model.UserStateOnSAST, nil)

	emailType := model.EmailTypeSAST
	_, err := users.UpdateAdminUser(context.Background(), user.ID,
		repository.AdminUserUpdate{EmailType: &emailType}, time.Now().UTC())
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("error = %v, want ErrInvalidArgument", err)
	}

	var reloaded model.User
	if err := database.First(&reloaded, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if reloaded.EmailType != model.EmailTypeNJUpt {
		t.Fatalf("email_type = %q, want it unchanged and consistent with the address",
			reloaded.EmailType)
	}
}

// The preallocation cap bounds reserved capacity, not the result. A limit above the
// cap must still return every row the query matches — a slice grows past its initial
// capacity, so capping it can only cost an append, never truncate. Swapping the cap
// into the SQL LIMIT instead would silently shorten pages.
func TestListAdminUsersHonoursALimitAboveThePreallocationCap(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	const seeded = 5
	for i := range seeded {
		adminSeed(t, database, fmt.Sprintf("b24040%d@njupt.edu.cn", i), fmt.Sprintf("用户%d", i),
			model.UserRoleMember, model.UserStateOnSAST, nil)
	}

	rows, total, err := users.ListAdminUsers(context.Background(),
		repository.AdminUserFilter{Limit: 10_000_000, Offset: 0})
	if err != nil {
		t.Fatalf("ListAdminUsers: %v", err)
	}
	if total != seeded {
		t.Fatalf("total = %d, want %d", total, seeded)
	}
	if len(rows) != seeded {
		t.Fatalf("rows = %d, want %d: the cap must bound the reservation, not the page",
			len(rows), seeded)
	}
}
