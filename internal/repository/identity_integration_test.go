package repository_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func TestIdentityRepositoryCountAndFind(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	identityRepository := repository.NewIdentity(database)
	user := createUserWithProfile(t, userRepository, "identity@njupt.edu.cn")

	identity := &model.Identity{
		UserID:     user.ID,
		Provider:   model.LoginMethodOtherMail,
		ProviderID: "bound@qq.com",
	}
	if err := identityRepository.CreateWithinLimit(context.Background(), identity, 2); err != nil {
		t.Fatalf("CreateWithinLimit() error = %v", err)
	}
	if identity.ID == 0 {
		t.Fatal("CreateWithinLimit() did not populate the generated ID")
	}

	count, err := identityRepository.CountByUserAndProvider(context.Background(), user.ID, model.LoginMethodOtherMail)
	if err != nil {
		t.Fatalf("CountByUserAndProvider() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("CountByUserAndProvider() = %d, want 1", count)
	}

	found, err := identityRepository.FindByProviderID(context.Background(), model.LoginMethodOtherMail, "bound@qq.com")
	if err != nil {
		t.Fatalf("FindByProviderID() error = %v", err)
	}
	if found.UserID != user.ID || found.ProviderID != "bound@qq.com" {
		t.Fatalf("FindByProviderID() = %#v, want the binding of user %d", found, user.ID)
	}

	_, err = identityRepository.FindByProviderID(context.Background(), model.LoginMethodOtherMail, "absent@qq.com")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindByProviderID(absent) error = %v, want ErrNotFound", err)
	}
}

// The other-mail cap must hold under concurrency: the repository locks the user
// row so parallel binds serialize instead of both passing a stale count check.
func TestIdentityRepositoryCreateWithinLimitIsAtomic(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	identityRepository := repository.NewIdentity(database)
	user := createUserWithProfile(t, userRepository, "cap@njupt.edu.cn")

	const (
		attempts = 5
		limit    = 2
	)
	var waitGroup sync.WaitGroup
	results := make([]error, attempts)
	for index := range attempts {
		waitGroup.Add(1)
		go func(slot int) {
			defer waitGroup.Done()
			results[slot] = identityRepository.CreateWithinLimit(context.Background(), &model.Identity{
				UserID:     user.ID,
				Provider:   model.LoginMethodOtherMail,
				ProviderID: fmt.Sprintf("concurrent%d@qq.com", slot),
			}, limit)
		}(index)
	}
	waitGroup.Wait()

	created := 0
	for slot, err := range results {
		switch {
		case err == nil:
			created++
		case errors.Is(err, repository.ErrLimitExceeded):
		default:
			t.Fatalf("attempt %d error = %v, want nil or ErrLimitExceeded", slot, err)
		}
	}
	if created != limit {
		t.Fatalf("created = %d, want exactly %d", created, limit)
	}

	count, err := identityRepository.CountByUserAndProvider(context.Background(), user.ID, model.LoginMethodOtherMail)
	if err != nil {
		t.Fatalf("CountByUserAndProvider() error = %v", err)
	}
	if count != limit {
		t.Fatalf("stored identities = %d, want %d", count, limit)
	}
}

func TestIdentityRepositoryCreateWithinLimitRejectsInvalidInput(t *testing.T) {
	database := setupDatabase(t)
	identityRepository := repository.NewIdentity(database)

	if err := identityRepository.CreateWithinLimit(context.Background(), nil, 2); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("CreateWithinLimit(nil) error = %v, want ErrInvalidArgument", err)
	}
	identity := &model.Identity{UserID: 1, Provider: model.LoginMethodOtherMail, ProviderID: "x@qq.com"}
	if err := identityRepository.CreateWithinLimit(context.Background(), identity, 0); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("CreateWithinLimit(limit=0) error = %v, want ErrInvalidArgument", err)
	}
	absent := &model.Identity{UserID: 999_999, Provider: model.LoginMethodOtherMail, ProviderID: "y@qq.com"}
	if err := identityRepository.CreateWithinLimit(context.Background(), absent, 2); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("CreateWithinLimit(absent user) error = %v, want ErrNotFound", err)
	}
}

func TestIdentityRepositoryListByUser(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	identityRepository := repository.NewIdentity(database)
	owner := createUserWithProfile(t, userRepository, "lister@njupt.edu.cn")
	stranger := createUserWithProfile(t, userRepository, "stranger@njupt.edu.cn")

	for _, providerID := range []string{"first@qq.com", "second@qq.com"} {
		identity := &model.Identity{UserID: owner.ID, Provider: model.LoginMethodOtherMail, ProviderID: providerID}
		if err := identityRepository.CreateWithinLimit(context.Background(), identity, 2); err != nil {
			t.Fatalf("CreateWithinLimit(%q) error = %v", providerID, err)
		}
	}
	foreign := &model.Identity{UserID: stranger.ID, Provider: model.LoginMethodOtherMail, ProviderID: "foreign@qq.com"}
	if err := identityRepository.CreateWithinLimit(context.Background(), foreign, 2); err != nil {
		t.Fatalf("CreateWithinLimit(foreign) error = %v", err)
	}

	identities, err := identityRepository.ListByUser(context.Background(), owner.ID)
	if err != nil {
		t.Fatalf("ListByUser() error = %v", err)
	}
	if len(identities) != 2 {
		t.Fatalf("ListByUser() = %d identities, want only the owner's 2", len(identities))
	}
	if identities[0].ID > identities[1].ID {
		t.Fatalf("ListByUser() = %v, want ascending IDs", identities)
	}
	for _, identity := range identities {
		if identity.UserID != owner.ID {
			t.Fatalf("identity %d belongs to user %d, want %d", identity.ID, identity.UserID, owner.ID)
		}
	}

	empty, err := identityRepository.ListByUser(context.Background(), 999_999)
	if err != nil {
		t.Fatalf("ListByUser(absent) error = %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ListByUser(absent) = %v, want empty", empty)
	}
}

// Ownership is part of the lookup, not a check the caller applies afterwards, so
// somebody else's binding ID reads exactly like a missing one.
func TestIdentityRepositoryFindAndDeleteAreOwnerScoped(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	identityRepository := repository.NewIdentity(database)
	owner := createUserWithProfile(t, userRepository, "owner@njupt.edu.cn")
	stranger := createUserWithProfile(t, userRepository, "other@njupt.edu.cn")

	mine := &model.Identity{UserID: owner.ID, Provider: model.LoginMethodOtherMail, ProviderID: "mine@qq.com"}
	if err := identityRepository.CreateWithinLimit(context.Background(), mine, 2); err != nil {
		t.Fatalf("CreateWithinLimit(mine) error = %v", err)
	}
	theirs := &model.Identity{UserID: stranger.ID, Provider: model.LoginMethodOtherMail, ProviderID: "theirs@qq.com"}
	if err := identityRepository.CreateWithinLimit(context.Background(), theirs, 2); err != nil {
		t.Fatalf("CreateWithinLimit(theirs) error = %v", err)
	}

	found, err := identityRepository.FindByIDAndUser(context.Background(), mine.ID, owner.ID)
	if err != nil {
		t.Fatalf("FindByIDAndUser(own) error = %v", err)
	}
	if found.ProviderID != "mine@qq.com" {
		t.Fatalf("FindByIDAndUser() = %#v, want mine@qq.com", found)
	}
	if _, err := identityRepository.FindByIDAndUser(context.Background(), theirs.ID, owner.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindByIDAndUser(foreign) error = %v, want ErrNotFound", err)
	}

	if err := identityRepository.DeleteByIDAndUser(context.Background(), theirs.ID, owner.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("DeleteByIDAndUser(foreign) error = %v, want ErrNotFound", err)
	}
	if _, err := identityRepository.FindByIDAndUser(context.Background(), theirs.ID, stranger.ID); err != nil {
		t.Fatalf("foreign identity was deleted: %v", err)
	}

	if err := identityRepository.DeleteByIDAndUser(context.Background(), mine.ID, owner.ID); err != nil {
		t.Fatalf("DeleteByIDAndUser(own) error = %v", err)
	}
	if _, err := identityRepository.FindByIDAndUser(context.Background(), mine.ID, owner.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("identity still present after delete: %v", err)
	}
	// A repeat delete reports ErrNotFound rather than success, so a caller that
	// raced a concurrent unbind of the same row does not report success twice.
	if err := identityRepository.DeleteByIDAndUser(context.Background(), mine.ID, owner.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("DeleteByIDAndUser(repeat) error = %v, want ErrNotFound", err)
	}
}

// V001 caps other_mail bindings at 2 per user with a trigger. Unbinding must free
// a slot, or a user who hits the cap can never swap an address.
func TestIdentityRepositoryDeleteFreesOtherMailSlot(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	identityRepository := repository.NewIdentity(database)
	user := createUserWithProfile(t, userRepository, "swap@njupt.edu.cn")

	first := &model.Identity{UserID: user.ID, Provider: model.LoginMethodOtherMail, ProviderID: "one@qq.com"}
	second := &model.Identity{UserID: user.ID, Provider: model.LoginMethodOtherMail, ProviderID: "two@qq.com"}
	for _, identity := range []*model.Identity{first, second} {
		if err := identityRepository.CreateWithinLimit(context.Background(), identity, 2); err != nil {
			t.Fatalf("CreateWithinLimit(%q) error = %v", identity.ProviderID, err)
		}
	}
	third := &model.Identity{UserID: user.ID, Provider: model.LoginMethodOtherMail, ProviderID: "three@qq.com"}
	if err := identityRepository.CreateWithinLimit(context.Background(), third, 2); !errors.Is(err, repository.ErrLimitExceeded) {
		t.Fatalf("CreateWithinLimit(third) error = %v, want ErrLimitExceeded", err)
	}

	if err := identityRepository.DeleteByIDAndUser(context.Background(), first.ID, user.ID); err != nil {
		t.Fatalf("DeleteByIDAndUser() error = %v", err)
	}
	replacement := &model.Identity{UserID: user.ID, Provider: model.LoginMethodOtherMail, ProviderID: "three@qq.com"}
	if err := identityRepository.CreateWithinLimit(context.Background(), replacement, 2); err != nil {
		t.Fatalf("CreateWithinLimit() after unbind error = %v, want a freed slot", err)
	}
}
