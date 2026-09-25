package repository_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func badgeFor(userID int64, key string) *model.Badge {
	return &model.Badge{UserID: userID, BadgeKey: key}
}

func TestBadgeRepositoryCreateAndFind(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	badges := repository.NewBadge(database)
	user := createUserWithProfile(t, userRepository, "badge-create@njupt.edu.cn")

	// EnabledAt is set by the service (from its Clock) rather than the DB
	// default: GORM's Create returns only the generated id, so a default-now
	// column would never be read back and the caller would hold a zero time.
	enabledAt := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	created := &model.Badge{UserID: user.ID, BadgeKey: "badge-key-create", EnabledAt: enabledAt}
	if err := badges.Create(context.Background(), created); err != nil {
		t.Fatalf("Create error = %v", err)
	}
	if created.ID == 0 {
		t.Fatalf("Create did not populate the generated id: %#v", created)
	}

	found, err := badges.FindByUserID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("FindByUserID error = %v", err)
	}
	if found.BadgeKey != "badge-key-create" {
		t.Fatalf("FindByUserID BadgeKey = %q, want %q", found.BadgeKey, "badge-key-create")
	}
	if !found.EnabledAt.Equal(enabledAt) {
		t.Fatalf("FindByUserID EnabledAt = %v, want %v", found.EnabledAt, enabledAt)
	}
}

func TestBadgeRepositoryCreateReportsAlreadyEnabled(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	badges := repository.NewBadge(database)
	user := createUserWithProfile(t, userRepository, "badge-dup@njupt.edu.cn")

	if err := badges.Create(context.Background(), badgeFor(user.ID, "badge-key-dup")); err != nil {
		t.Fatalf("first Create error = %v", err)
	}
	err := badges.Create(context.Background(), badgeFor(user.ID, "badge-key-dup-2"))
	if !errors.Is(err, repository.ErrBadgeAlreadyEnabled) {
		t.Fatalf("second Create error = %v, want ErrBadgeAlreadyEnabled", err)
	}
}

func TestBadgeRepositoryFindBadgeTarget(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	badges := repository.NewBadge(database)
	user := createUserWithProfile(t, userRepository, "badge-target@njupt.edu.cn")

	if err := badges.Create(context.Background(), badgeFor(user.ID, "badge-key-target")); err != nil {
		t.Fatalf("Create error = %v", err)
	}

	found, err := badges.FindBadgeTarget(context.Background(), "badge-key-target")
	if err != nil {
		t.Fatalf("FindBadgeTarget error = %v", err)
	}
	if found.UserID != user.ID {
		t.Fatalf("FindBadgeTarget UserID = %d, want %d", found.UserID, user.ID)
	}

	if _, err := badges.FindBadgeTarget(context.Background(), "badge-key-unknown"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindBadgeTarget(unknown) error = %v, want ErrNotFound", err)
	}
	if _, err := badges.FindBadgeTarget(context.Background(), ""); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("FindBadgeTarget(empty) error = %v, want ErrInvalidArgument", err)
	}
}

func TestBadgeRepositoryFindBadgeTargetHidesDeletedUsers(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	badges := repository.NewBadge(database)
	user := createUserWithProfile(t, userRepository, "badge-deleted@njupt.edu.cn")

	if err := badges.Create(context.Background(), badgeFor(user.ID, "badge-key-deleted")); err != nil {
		t.Fatalf("Create error = %v", err)
	}
	if err := database.Model(&model.User{}).Where("id = ?", user.ID).
		Update("state", model.UserStateDeleted).Error; err != nil {
		t.Fatalf("mark user deleted: %v", err)
	}

	// A deleted owner's key must stop resolving: FindPublicCardByUserID hides
	// deleted users for the same reason, and the badge must not outlive it.
	if _, err := badges.FindBadgeTarget(context.Background(), "badge-key-deleted"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindBadgeTarget(deleted owner) error = %v, want ErrNotFound", err)
	}
}

func TestBadgeRepositoryDeleteIsIdempotent(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	badges := repository.NewBadge(database)
	user := createUserWithProfile(t, userRepository, "badge-delete@njupt.edu.cn")

	if err := badges.Create(context.Background(), badgeFor(user.ID, "badge-key-delete")); err != nil {
		t.Fatalf("Create error = %v", err)
	}

	removed, err := badges.DeleteByUserID(context.Background(), user.ID)
	if err != nil || !removed {
		t.Fatalf("DeleteByUserID = (%v, %v), want (true, nil)", removed, err)
	}
	_, findErr := badges.FindByUserID(context.Background(), user.ID)
	if !errors.Is(findErr, repository.ErrNotFound) {
		t.Fatalf("FindByUserID after delete error = %v, want ErrNotFound", findErr)
	}

	// Disabling a badge that does not exist is a no-op, not an error.
	removed, err = badges.DeleteByUserID(context.Background(), user.ID)
	if err != nil || removed {
		t.Fatalf("second DeleteByUserID = (%v, %v), want (false, nil)", removed, err)
	}
}

func TestBadgeRepositoryPauseAndResumeKeepTheKey(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	badges := repository.NewBadge(database)
	user := createUserWithProfile(t, userRepository, "badge-pause@njupt.edu.cn")

	if err := badges.Create(context.Background(), badgeFor(user.ID, "badge-key-pause")); err != nil {
		t.Fatalf("Create error = %v", err)
	}

	// Pause: the row stays, the public lookup stops resolving.
	paused, err := badges.Disable(context.Background(), user.ID, time.Now())
	if err != nil || !paused {
		t.Fatalf("Disable = (%v, %v), want (true, nil)", paused, err)
	}
	row, err := badges.FindByUserID(context.Background(), user.ID)
	if err != nil || row.BadgeKey != "badge-key-pause" {
		t.Fatalf("FindByUserID after pause = (%v, %v), want the row kept", row, err)
	}
	_, targetErr := badges.FindBadgeTarget(context.Background(), "badge-key-pause")
	if !errors.Is(targetErr, repository.ErrNotFound) {
		t.Fatalf("FindBadgeTarget(paused) error = %v, want ErrNotFound", targetErr)
	}

	// Pausing again is a no-op.
	pausedAgain, err := badges.Disable(context.Background(), user.ID, time.Now())
	if err != nil || pausedAgain {
		t.Fatalf("second Disable = (%v, %v), want (false, nil)", pausedAgain, err)
	}

	// Resume: the same key resolves again.
	resumed, err := badges.ReEnable(context.Background(), user.ID, time.Now())
	if err != nil || !resumed {
		t.Fatalf("ReEnable = (%v, %v), want (true, nil)", resumed, err)
	}
	resumedTarget, resumedTargetErr := badges.FindBadgeTarget(context.Background(), "badge-key-pause")
	if resumedTargetErr != nil || resumedTarget == nil {
		t.Fatalf("FindBadgeTarget(resumed) = (%v, %v), want the row", resumedTarget, resumedTargetErr)
	}
	// Resuming an already-sharing row is a no-op.
	resumedAgain, err := badges.ReEnable(context.Background(), user.ID, time.Now())
	if err != nil || resumedAgain {
		t.Fatalf("second ReEnable = (%v, %v), want (false, nil)", resumedAgain, err)
	}
}
