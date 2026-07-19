package repository_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

const tokenFamilyAdvisoryLockNamespace int32 = 0x53415354

func TestTokenRepositoryCreatePairAllowsRotationAfterRefreshRevocation(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotated-family@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotated-family"

	createTokenPair(t, tokenRepository, "rotation-existing", familyID, 0, client.ID, user.ID)
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("family_id = ? AND sequence = ?", familyID, 0).
		Update("revoked_at", time.Now()).Error; err != nil {
		t.Fatalf("revoke rotated refresh token: %v", err)
	}

	access := accessToken("rotation-next-access", client.ID, user.ID, &familyID)
	refresh := refreshToken("rotation-next-refresh", familyID, 1, client.ID, user.ID)
	if err := tokenRepository.CreatePair(context.Background(), access, refresh); err != nil {
		t.Fatalf("CreatePair() after refresh rotation error = %v", err)
	}
	if access.ID == 0 || refresh.ID == 0 {
		t.Fatalf("rotated token-pair IDs = %d/%d, want persisted records", access.ID, refresh.ID)
	}
}

func TestTokenRepositoryCreatePairRejectsRevokedFamily(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "revoked-family@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "revoked-family"

	createTokenPair(t, tokenRepository, "revoked-existing", familyID, 0, client.ID, user.ID)
	if err := tokenRepository.RevokeFamily(context.Background(), familyID, time.Now()); err != nil {
		t.Fatalf("RevokeFamily() error = %v", err)
	}

	access := accessToken("revoked-rejected-access", client.ID, user.ID, &familyID)
	refresh := refreshToken("revoked-rejected-refresh", familyID, 1, client.ID, user.ID)
	err := tokenRepository.CreatePair(context.Background(), access, refresh)
	if !errors.Is(err, repository.ErrTokenFamilyRevoked) {
		t.Fatalf("CreatePair() error = %v, want ErrTokenFamilyRevoked", err)
	}

	assertTokenPairAbsent(t, database, access.TokenID, refresh.TokenHash)
}

func TestTokenRepositoryFamilyOperationsWaitForSameAdvisoryLock(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "family-lock@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)

	t.Run("CreatePair", func(t *testing.T) {
		familyID := "locked-create-family"
		access := accessToken("locked-create-access", client.ID, user.ID, &familyID)
		refresh := refreshToken("locked-create-refresh", familyID, 0, client.ID, user.ID)

		assertWaitsForTokenFamilyLock(t, database, familyID, func(ctx context.Context) error {
			return tokenRepository.CreatePair(ctx, access, refresh)
		})
	})

	t.Run("RevokeFamily", func(t *testing.T) {
		familyID := "locked-revoke-family"
		createTokenPair(t, tokenRepository, "locked-revoke", familyID, 0, client.ID, user.ID)

		assertWaitsForTokenFamilyLock(t, database, familyID, func(ctx context.Context) error {
			return tokenRepository.RevokeFamily(ctx, familyID, time.Now())
		})
	})
}

func assertWaitsForTokenFamilyLock(
	t *testing.T,
	database *gorm.DB,
	familyID string,
	operation func(context.Context) error,
) {
	t.Helper()

	lockTransaction := database.Begin()
	if lockTransaction.Error != nil {
		t.Fatalf("begin lock transaction: %v", lockTransaction.Error)
	}
	lockReleased := false
	defer func() {
		if !lockReleased {
			_ = lockTransaction.Rollback().Error
		}
	}()

	if err := lockTransaction.Exec(
		"SELECT pg_advisory_xact_lock(?, hashtext(?))",
		tokenFamilyAdvisoryLockNamespace,
		familyID,
	).Error; err != nil {
		t.Fatalf("acquire external token-family lock: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		result <- operation(ctx)
	}()
	<-started

	select {
	case err := <-result:
		t.Fatalf("operation completed while family lock was held: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	if err := lockTransaction.Rollback().Error; err != nil {
		t.Fatalf("release external token-family lock: %v", err)
	}
	lockReleased = true

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("operation after family lock release: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("operation remained blocked after family lock release: %v", ctx.Err())
	}
}

func assertTokenPairAbsent(t *testing.T, database *gorm.DB, tokenID string, tokenHash string) {
	t.Helper()

	var accessCount int64
	if err := database.Model(&model.OAuthAccessToken{}).
		Where("token_id = ?", tokenID).
		Count(&accessCount).Error; err != nil {
		t.Fatalf("count rejected access token: %v", err)
	}
	var refreshCount int64
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("token_hash = ?", tokenHash).
		Count(&refreshCount).Error; err != nil {
		t.Fatalf("count rejected refresh token: %v", err)
	}
	if accessCount != 0 || refreshCount != 0 {
		t.Fatalf("rejected token-pair counts = %d access, %d refresh; want 0 each", accessCount, refreshCount)
	}
}
