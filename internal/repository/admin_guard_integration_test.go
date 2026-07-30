package repository_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// The system must never be left without an administrator: the endpoints that would
// promote a replacement are the ones that just became unreachable, so recovery
// needs direct database access.
func TestUpdateAdminUserRefusesDemotingTheLastAdmin(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	admin := adminSeed(t, database, "solo@sast.fun", "唯一管理员",
		model.UserRoleAdmin, model.UserStateOnSAST, nil)
	// A member and a closed admin: neither counts as an active administrator, so
	// neither may stand in for the one being demoted.
	adminSeed(t, database, "member@njupt.edu.cn", "普通成员",
		model.UserRoleMember, model.UserStateOnSAST, nil)
	adminSeed(t, database, "closed@sast.fun", "已注销管理员",
		model.UserRoleAdmin, model.UserStateDeleted, nil)

	role := model.UserRoleMember
	_, err := users.UpdateAdminUser(context.Background(), admin.ID,
		repository.AdminUserUpdate{Role: &role}, true, true, time.Now().UTC())
	if !errors.Is(err, repository.ErrLastAdmin) {
		t.Fatalf("error = %v, want ErrLastAdmin", err)
	}

	var reloaded model.User
	if err := database.First(&reloaded, admin.ID).Error; err != nil {
		t.Fatalf("reload admin: %v", err)
	}
	if reloaded.Role != model.UserRoleAdmin {
		t.Fatalf("role = %q, want the demotion rolled back", reloaded.Role)
	}
	if reloaded.TokenVersion != admin.TokenVersion {
		t.Fatalf("token_version = %d, want the whole transaction rolled back at %d",
			reloaded.TokenVersion, admin.TokenVersion)
	}
}

func TestSoftDeleteRefusesClosingTheLastAdmin(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	admin := adminSeed(t, database, "solo2@sast.fun", "唯一管理员",
		model.UserRoleAdmin, model.UserStateOnSAST, nil)

	_, err := users.SoftDeleteAndRevokeSessions(context.Background(), admin.ID, time.Now().UTC())
	if !errors.Is(err, repository.ErrLastAdmin) {
		t.Fatalf("error = %v, want ErrLastAdmin", err)
	}
	var reloaded model.User
	if err := database.First(&reloaded, admin.ID).Error; err != nil {
		t.Fatalf("reload admin: %v", err)
	}
	if reloaded.State != model.UserStateOnSAST {
		t.Fatalf("state = %q, want the account left open", reloaded.State)
	}
}

// With a second administrator present the demotion goes through: the guard is about
// the last one, not about administrators in general.
func TestUpdateAdminUserAllowsDemotionWhenAnotherAdminRemains(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	first := adminSeed(t, database, "admin1@sast.fun", "管理员一",
		model.UserRoleAdmin, model.UserStateOnSAST, nil)
	adminSeed(t, database, "admin2@sast.fun", "管理员二",
		model.UserRoleAdmin, model.UserStateOnSAST, nil)

	role := model.UserRoleMember
	if _, err := users.UpdateAdminUser(context.Background(), first.ID,
		repository.AdminUserUpdate{Role: &role}, true, true, time.Now().UTC()); err != nil {
		t.Fatalf("UpdateAdminUser: %v", err)
	}
}

// Closing a non-admin account must not be blocked when there happens to be no
// administrator at all: this write is not what removed one, and refusing it would
// make the console unusable rather than safer.
func TestSoftDeleteAllowsNonAdminWithNoAdminPresent(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	member := adminSeed(t, database, "lonely@njupt.edu.cn", "普通成员",
		model.UserRoleMember, model.UserStateOnSAST, nil)

	if _, err := users.SoftDeleteAndRevokeSessions(context.Background(),
		member.ID, time.Now().UTC()); err != nil {
		t.Fatalf("SoftDeleteAndRevokeSessions: %v", err)
	}
}

// This is the case the advisory lock exists for. Two administrators demoting each
// other at the same time both read "one other admin remains" if the count is not
// serialized, and both commit — leaving zero. Exactly one must win.
func TestConcurrentDemotionsCannotRemoveEveryAdmin(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	first := adminSeed(t, database, "race1@sast.fun", "管理员一",
		model.UserRoleAdmin, model.UserStateOnSAST, nil)
	second := adminSeed(t, database, "race2@sast.fun", "管理员二",
		model.UserRoleAdmin, model.UserStateOnSAST, nil)

	role := model.UserRoleMember
	var waitGroup sync.WaitGroup
	results := make([]error, 2)
	start := make(chan struct{})
	for index, target := range []int64{first.ID, second.ID} {
		waitGroup.Add(1)
		go func(index int, userID int64) {
			defer waitGroup.Done()
			<-start
			_, err := users.UpdateAdminUser(context.Background(), userID,
				repository.AdminUserUpdate{Role: &role}, true, true, time.Now().UTC())
			results[index] = err
		}(index, target)
	}
	close(start)
	waitGroup.Wait()

	var succeeded, refused int
	for _, err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, repository.ErrLastAdmin):
			refused++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 || refused != 1 {
		t.Fatalf("outcomes = %d succeeded, %d refused; want exactly one of each",
			succeeded, refused)
	}

	var remaining int64
	if err := database.Model(&model.User{}).
		Where("role = ? AND state <> ?", model.UserRoleAdmin, model.UserStateDeleted).
		Count(&remaining).Error; err != nil {
		t.Fatalf("count admins: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("remaining active admins = %d, want 1", remaining)
	}
}

// The same race across the two different write paths: one demotes, the other
// closes. Both take the same advisory key, so they serialize against each other.
func TestConcurrentDemotionAndSoftDeleteKeepOneAdmin(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	first := adminSeed(t, database, "mix1@sast.fun", "管理员一",
		model.UserRoleAdmin, model.UserStateOnSAST, nil)
	second := adminSeed(t, database, "mix2@sast.fun", "管理员二",
		model.UserRoleAdmin, model.UserStateOnSAST, nil)

	role := model.UserRoleMember
	var waitGroup sync.WaitGroup
	results := make([]error, 2)
	start := make(chan struct{})

	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		<-start
		_, err := users.UpdateAdminUser(context.Background(), first.ID,
			repository.AdminUserUpdate{Role: &role}, true, true, time.Now().UTC())
		results[0] = err
	}()
	go func() {
		defer waitGroup.Done()
		<-start
		_, err := users.SoftDeleteAndRevokeSessions(context.Background(), second.ID, time.Now().UTC())
		results[1] = err
	}()
	close(start)
	waitGroup.Wait()

	var succeeded, refused int
	for _, err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, repository.ErrLastAdmin):
			refused++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 || refused != 1 {
		t.Fatalf("outcomes = %d succeeded, %d refused; want exactly one of each",
			succeeded, refused)
	}
}
