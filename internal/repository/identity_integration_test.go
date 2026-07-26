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
