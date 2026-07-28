package repository_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func stringPtr(value string) *string { return &value }

func TestUserRepositoryUpdateProfileAppliesBothTables(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "update@njupt.edu.cn")

	department := model.DepartmentSoftware
	college := model.CollegeComputerSoftwareCybersecurity
	updated, err := userRepository.UpdateProfile(context.Background(), user.ID, repository.ProfileUpdate{
		Name:       stringPtr("新名字"),
		Major:      stringPtr("软件工程"),
		College:    &college,
		Nickname:   stringPtr("新昵称"),
		Department: &department,
		BlogURL:    stringPtr("https://blog.example.com"),
	})
	if err != nil {
		t.Fatalf("UpdateProfile() error = %v", err)
	}
	if updated.Name != "新名字" || updated.Major != "软件工程" || updated.College != college {
		t.Fatalf("user fields = %#v, want the submitted values", updated)
	}
	if updated.Profile == nil {
		t.Fatal("UpdateProfile() returned no profile")
	}
	if got := updated.Profile.Nickname; got == nil || *got != "新昵称" {
		t.Fatalf("nickname = %v, want 新昵称", got)
	}
	if got := updated.Profile.Department; got == nil || *got != department {
		t.Fatalf("department = %v, want software", got)
	}
	// The V001 trigger bumps updated_at on every UPDATE, so the write really landed.
	if !updated.UpdatedAt.After(user.CreatedAt) && !updated.UpdatedAt.Equal(user.CreatedAt) {
		t.Fatalf("updated_at = %v, want refreshed", updated.UpdatedAt)
	}
}

// Absent fields must survive the update: a partial PUT that silently blanked
// unsent columns would erase data the client never mentioned.
func TestUserRepositoryUpdateProfileLeavesAbsentFieldsAlone(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "partial@njupt.edu.cn")

	if _, err := userRepository.UpdateProfile(context.Background(), user.ID, repository.ProfileUpdate{
		Nickname: stringPtr("只改昵称"),
	}); err != nil {
		t.Fatalf("UpdateProfile() error = %v", err)
	}
	reloaded, err := userRepository.FindByID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if reloaded.Name != user.Name || reloaded.PhoneNumber != user.PhoneNumber || reloaded.StudentID != user.StudentID {
		t.Fatalf("user = %#v, want untouched identity fields", reloaded)
	}
	if reloaded.LoginEmail != user.LoginEmail || reloaded.Role != user.Role || reloaded.State != user.State {
		t.Fatalf("user = %#v, want untouched permission fields", reloaded)
	}
}

// An empty string on a nullable display column writes SQL NULL, which is how the
// API expresses "clear this field".
func TestUserRepositoryUpdateProfileClearsNullableColumns(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "clear@njupt.edu.cn")

	department := model.DepartmentMedia
	if _, err := userRepository.UpdateProfile(context.Background(), user.ID, repository.ProfileUpdate{
		Intro:      stringPtr("先写一段"),
		Department: &department,
	}); err != nil {
		t.Fatalf("UpdateProfile(set) error = %v", err)
	}
	// An empty Department is the clear sentinel: the enum has no "" member, so it
	// must reach PostgreSQL as NULL rather than as an invalid enum literal.
	clearDepartment := model.Department("")
	cleared, err := userRepository.UpdateProfile(context.Background(), user.ID, repository.ProfileUpdate{
		Intro:      stringPtr(""),
		Department: &clearDepartment,
	})
	if err != nil {
		t.Fatalf("UpdateProfile(clear) error = %v", err)
	}
	if cleared.Profile.Intro != nil {
		t.Fatalf("intro = %v, want NULL", *cleared.Profile.Intro)
	}
	if cleared.Profile.Department != nil {
		t.Fatalf("department = %v, want NULL", *cleared.Profile.Department)
	}
}

// profile rows are created with the account, but a row imported before the
// registration flow existed would otherwise make display fields silently
// unwritable while the response still reported success.
func TestUserRepositoryUpdateProfileCreatesMissingProfileRow(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "orphan@njupt.edu.cn")
	if err := database.Exec("DELETE FROM profile WHERE user_id = ?", user.ID).Error; err != nil {
		t.Fatalf("delete profile row: %v", err)
	}

	updated, err := userRepository.UpdateProfile(context.Background(), user.ID, repository.ProfileUpdate{
		Nickname: stringPtr("重新创建"),
	})
	if err != nil {
		t.Fatalf("UpdateProfile() error = %v", err)
	}
	if updated.Profile == nil {
		t.Fatal("profile row was not created")
	}
	if got := updated.Profile.Nickname; got == nil || *got != "重新创建" {
		t.Fatalf("nickname = %v, want 重新创建", got)
	}
}

func TestUserRepositoryUpdateProfileRejectsUnknownUser(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)

	_, err := userRepository.UpdateProfile(context.Background(), 999999, repository.ProfileUpdate{
		Name: stringPtr("不存在"),
	})
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("UpdateProfile(unknown) error = %v, want ErrNotFound", err)
	}
	// Also when only profile columns are touched, so the upsert path checks the
	// owner instead of relying on the foreign key to fail.
	_, err = userRepository.UpdateProfile(context.Background(), 999999, repository.ProfileUpdate{
		Nickname: stringPtr("不存在"),
	})
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("UpdateProfile(unknown, profile only) error = %v, want ErrNotFound", err)
	}
}

func TestUserRepositoryUpdateProfileRejectsEmptyUpdate(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "noop@njupt.edu.cn")

	_, err := userRepository.UpdateProfile(context.Background(), user.ID, repository.ProfileUpdate{})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("UpdateProfile(empty) error = %v, want ErrInvalidArgument", err)
	}
}

// student_id is UNIQUE, so a colliding edit must surface the constraint name the
// service dispatches on rather than a generic error.
func TestUserRepositoryUpdateProfileSurfacesStudentIDConflict(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	first := createUserWithProfile(t, userRepository, "first@njupt.edu.cn")
	second := createUserWithProfile(t, userRepository, "second@njupt.edu.cn")

	_, err := userRepository.UpdateProfile(context.Background(), second.ID, repository.ProfileUpdate{
		StudentID: &first.StudentID,
	})
	if err == nil {
		t.Fatal("UpdateProfile() error = nil, want a unique violation")
	}
	if !strings.Contains(err.Error(), "user_student_id_key") {
		t.Fatalf("UpdateProfile() error = %v, want the student_id constraint name", err)
	}
}

func TestUserRepositoryFindPublicCard(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "card@njupt.edu.cn")
	department := model.DepartmentSoftware
	if _, err := userRepository.UpdateProfile(context.Background(), user.ID, repository.ProfileUpdate{
		Nickname:   stringPtr("卡片昵称"),
		Department: &department,
		Intro:      stringPtr("自我介绍"),
		GitHubURL:  stringPtr("https://github.com/example"),
	}); err != nil {
		t.Fatalf("UpdateProfile() error = %v", err)
	}

	card, err := userRepository.FindPublicCardByUserID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("FindPublicCardByUserID() error = %v", err)
	}
	if card.ID != user.ID {
		t.Fatalf("card ID = %d, want %d", card.ID, user.ID)
	}
	if got := card.Nickname; got == nil || *got != "卡片昵称" {
		t.Fatalf("nickname = %v, want 卡片昵称", got)
	}
	if got := card.Department; got == nil || *got != department {
		t.Fatalf("department = %v, want software", got)
	}
	if card.Avatar != nil {
		t.Fatalf("avatar = %v, want NULL", *card.Avatar)
	}
}

// The card endpoint needs no authentication, so a soft-deleted account must be
// invisible rather than publishing the profile of someone who asked to be removed.
func TestUserRepositoryFindPublicCardHidesDeletedUsers(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "deleted@njupt.edu.cn")
	if err := database.Exec(`UPDATE "user" SET state = ? WHERE id = ?`, model.UserStateDeleted, user.ID).Error; err != nil {
		t.Fatalf("soft delete user: %v", err)
	}

	_, err := userRepository.FindPublicCardByUserID(context.Background(), user.ID)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindPublicCardByUserID(deleted) error = %v, want ErrNotFound", err)
	}
}

// A user whose profile row is missing still has a card; the display fields are
// simply NULL, which is why the join is a LEFT JOIN.
func TestUserRepositoryFindPublicCardWithoutProfileRow(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "noprofile@njupt.edu.cn")
	if err := database.Exec("DELETE FROM profile WHERE user_id = ?", user.ID).Error; err != nil {
		t.Fatalf("delete profile row: %v", err)
	}

	card, err := userRepository.FindPublicCardByUserID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("FindPublicCardByUserID() error = %v", err)
	}
	if card.ID != user.ID || card.Nickname != nil || card.Intro != nil {
		t.Fatalf("card = %#v, want the ID with NULL display fields", card)
	}
}

func TestUserRepositoryFindPublicCardRejectsUnknownAndNonPositive(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)

	for _, id := range []int64{0, -1, 999999} {
		if _, err := userRepository.FindPublicCardByUserID(context.Background(), id); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("FindPublicCardByUserID(%d) error = %v, want ErrNotFound", id, err)
		}
	}
}

// Submitting the value a column already holds must not be mistaken for a missing
// user: RowsAffected drives the ErrNotFound decision, so an UPDATE that changes
// nothing has to still report a matched row.
func TestUserRepositoryUpdateProfileAcceptsUnchangedValue(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "idempotent@njupt.edu.cn")

	for attempt := range 2 {
		updated, err := userRepository.UpdateProfile(context.Background(), user.ID, repository.ProfileUpdate{
			Name:     stringPtr("同一个名字"),
			Nickname: stringPtr("同一个昵称"),
		})
		if err != nil {
			t.Fatalf("UpdateProfile() attempt %d error = %v", attempt+1, err)
		}
		if updated.Name != "同一个名字" {
			t.Fatalf("attempt %d name = %q, want 同一个名字", attempt+1, updated.Name)
		}
	}
}
