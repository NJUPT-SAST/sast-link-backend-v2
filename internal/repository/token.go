package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"gorm.io/gorm"
)

const tokenFamilyAdvisoryLockNamespace int32 = 0x53415354

// ErrTokenFamilyRevoked indicates that a token pair cannot be added to a
// family that already contains revoked token metadata.
var ErrTokenFamilyRevoked = errors.New("token family is revoked")

// TokenRepository persists and revokes OAuth token metadata.
type TokenRepository struct {
	database *gorm.DB
}

// NewToken constructs a TokenRepository backed by database.
func NewToken(database *gorm.DB) *TokenRepository {
	return &TokenRepository{database: database}
}

// CreatePair creates access and refresh token records atomically.
func (r *TokenRepository) CreatePair(
	ctx context.Context,
	access *model.OAuthAccessToken,
	refresh *model.OAuthRefreshToken,
) error {
	if err := validateTokenPair(access, refresh); err != nil {
		return err
	}

	return r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		familyID := *access.FamilyID
		if err := lockTokenFamily(transaction, familyID); err != nil {
			return fmt.Errorf("lock token family: %w", err)
		}

		familyRevoked, err := tokenFamilyHasRevokedAccess(transaction, familyID)
		if err != nil {
			return fmt.Errorf("check token family revocation: %w", err)
		}
		if familyRevoked {
			return ErrTokenFamilyRevoked
		}

		if err := transaction.Create(access).Error; err != nil {
			return fmt.Errorf("create access token: %w", err)
		}
		if err := transaction.Create(refresh).Error; err != nil {
			return fmt.Errorf("create refresh token: %w", err)
		}
		return nil
	})
}

func lockTokenFamily(transaction *gorm.DB, familyID string) error {
	return transaction.Exec(
		"SELECT pg_advisory_xact_lock(?, hashtext(?))",
		tokenFamilyAdvisoryLockNamespace,
		familyID,
	).Error
}

func tokenFamilyHasRevokedAccess(transaction *gorm.DB, familyID string) (bool, error) {
	var revoked bool
	err := transaction.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM oauth_access_tokens
			WHERE family_id = ? AND revoked_at IS NOT NULL
		)`, familyID).Scan(&revoked).Error
	return revoked, err
}

func validateTokenPair(access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) error {
	if access == nil || refresh == nil {
		return errors.New("create token pair: access and refresh tokens are required")
	}
	if access.FamilyID == nil || *access.FamilyID != refresh.FamilyID {
		return errors.New("create token pair: family IDs do not match")
	}
	if access.ClientID != refresh.ClientID {
		return errors.New("create token pair: client IDs do not match")
	}
	if access.UserID != refresh.UserID {
		return errors.New("create token pair: user IDs do not match")
	}
	return nil
}

// FindRefreshToken finds a refresh token by its opaque token hash.
func (r *TokenRepository) FindRefreshToken(
	ctx context.Context,
	tokenHash string,
) (*model.OAuthRefreshToken, error) {
	var refresh model.OAuthRefreshToken
	err := r.database.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&refresh).Error
	if err == nil {
		return &refresh, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find refresh token: %w", err)
}

// RevokeFamily revokes unrevoked access and refresh tokens in one token family.
// Revoking a family without existing rows is a no-op; it does not create a tombstone.
func (r *TokenRepository) RevokeFamily(
	ctx context.Context,
	familyID string,
	revokedAt time.Time,
) error {
	return r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := lockTokenFamily(transaction, familyID); err != nil {
			return fmt.Errorf("lock token family: %w", err)
		}

		if err := transaction.Model(&model.OAuthAccessToken{}).
			Where("family_id = ? AND revoked_at IS NULL", familyID).
			Update("revoked_at", revokedAt).Error; err != nil {
			return fmt.Errorf("revoke access token family: %w", err)
		}
		if err := transaction.Model(&model.OAuthRefreshToken{}).
			Where("family_id = ? AND revoked_at IS NULL", familyID).
			Update("revoked_at", revokedAt).Error; err != nil {
			return fmt.Errorf("revoke refresh token family: %w", err)
		}
		return nil
	})
}
