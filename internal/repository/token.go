package repository

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

const tokenFamilyAdvisoryLockNamespace int32 = 0x53415354

// ErrTokenFamilyRevoked indicates that a token pair cannot be added to a
// family that already contains revoked token metadata.
var ErrTokenFamilyRevoked = errors.New("token family is revoked")

// ErrTokenReplay indicates refresh-token reuse or replay within a known token family.
var ErrTokenReplay = errors.New("repository: token replay")

// ErrTokenExpired indicates that token metadata is already expired.
var ErrTokenExpired = errors.New("repository: token expired")

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
		if err := validateTokenFamilyAppend(transaction, refresh); err != nil {
			return err
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

// RotateRefreshToken atomically rotates currentRefreshTokenHash to a new access/refresh pair.
func (r *TokenRepository) RotateRefreshToken(
	ctx context.Context,
	currentRefreshTokenHash string,
	newAccess *model.OAuthAccessToken,
	newRefresh *model.OAuthRefreshToken,
	revokedAt time.Time,
) error {
	if currentRefreshTokenHash == "" {
		return fmt.Errorf("%w: current refresh token hash is empty", ErrInvalidArgument)
	}
	if revokedAt.IsZero() {
		return fmt.Errorf("%w: revoked time is zero", ErrInvalidArgument)
	}
	if err := validateTokenPair(newAccess, newRefresh); err != nil {
		return err
	}

	familyID, err := r.findRefreshTokenFamilyID(ctx, currentRefreshTokenHash)
	if err != nil {
		return err
	}

	replayDetected := false
	transactionErr := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if lockErr := lockTokenFamily(transaction, familyID); lockErr != nil {
			return fmt.Errorf("lock token family: %w", lockErr)
		}
		rotationTime := time.Now().UTC()

		current, lockErr := findRefreshTokenForUpdate(transaction, currentRefreshTokenHash)
		if lockErr != nil {
			return lockErr
		}
		if current.FamilyID != familyID {
			return fmt.Errorf("%w: refresh token family changed during rotation", ErrInvalidArgument)
		}
		if current.RevokedAt != nil {
			if revokeErr := revokeFamilyInTransaction(transaction, familyID, rotationTime); revokeErr != nil {
				return revokeErr
			}
			replayDetected = true
			return nil
		}
		if validationErr := validateRefreshRotation(current, newAccess, newRefresh); validationErr != nil {
			return validationErr
		}

		if !current.ExpiresAt.After(rotationTime) {
			return ErrTokenExpired
		}
		familyRevoked, familyErr := tokenFamilyHasRevokedAccess(transaction, familyID)
		if familyErr != nil {
			return fmt.Errorf("check token family revocation: %w", familyErr)
		}
		if familyRevoked {
			if revokeErr := revokeFamilyInTransaction(transaction, familyID, rotationTime); revokeErr != nil {
				return revokeErr
			}
			replayDetected = true
			return nil
		}

		result := transaction.Model(&model.OAuthRefreshToken{}).
			Where("id = ? AND revoked_at IS NULL", current.ID).
			Update("revoked_at", rotationTime)
		if result.Error != nil {
			return fmt.Errorf("revoke current refresh token: %w", result.Error)
		}
		if result.RowsAffected != 1 {
			return fmt.Errorf("revoke current refresh token: %w", ErrTokenReplay)
		}
		if createErr := transaction.Create(newAccess).Error; createErr != nil {
			return fmt.Errorf("create rotated access token: %w", createErr)
		}
		if createErr := transaction.Create(newRefresh).Error; createErr != nil {
			return fmt.Errorf("create rotated refresh token: %w", createErr)
		}
		return nil
	})
	if transactionErr != nil {
		return transactionErr
	}
	if replayDetected {
		return ErrTokenReplay
	}
	return nil
}

func (r *TokenRepository) findRefreshTokenFamilyID(ctx context.Context, tokenHash string) (string, error) {
	var refresh model.OAuthRefreshToken
	err := r.database.WithContext(ctx).Select("family_id").Where("token_hash = ?", tokenHash).First(&refresh).Error
	if err == nil {
		return refresh.FamilyID, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", ErrNotFound
	}
	return "", fmt.Errorf("find refresh token family: %w", err)
}

func findRefreshTokenForUpdate(transaction *gorm.DB, tokenHash string) (*model.OAuthRefreshToken, error) {
	var refresh model.OAuthRefreshToken
	err := transaction.Clauses(clause.Locking{Strength: "UPDATE"}).Where("token_hash = ?", tokenHash).First(&refresh).Error
	if err == nil {
		return &refresh, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("lock refresh token: %w", err)
}

func validateRefreshRotation(
	current *model.OAuthRefreshToken,
	newAccess *model.OAuthAccessToken,
	newRefresh *model.OAuthRefreshToken,
) error {
	if *newAccess.FamilyID != current.FamilyID || newRefresh.FamilyID != current.FamilyID {
		return fmt.Errorf("%w: rotated token pair family ID does not match current refresh token", ErrInvalidArgument)
	}
	if newAccess.ClientID != current.ClientID || newRefresh.ClientID != current.ClientID {
		return fmt.Errorf("%w: rotated token pair client ID does not match current refresh token", ErrInvalidArgument)
	}
	if newAccess.UserID != current.UserID || newRefresh.UserID != current.UserID {
		return fmt.Errorf("%w: rotated token pair user ID does not match current refresh token", ErrInvalidArgument)
	}
	if newRefresh.Sequence != current.Sequence+1 {
		return fmt.Errorf("%w: rotated refresh sequence = %d, want %d", ErrInvalidArgument, newRefresh.Sequence, current.Sequence+1)
	}
	if !sameScopes(newAccess.Scopes, current.Scopes) || !sameScopes(newRefresh.Scopes, current.Scopes) {
		return fmt.Errorf("%w: rotated token scopes do not match current refresh token", ErrInvalidArgument)
	}
	return nil
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

func validateTokenFamilyAppend(transaction *gorm.DB, refresh *model.OAuthRefreshToken) error {
	var existing []model.OAuthRefreshToken
	if err := transaction.
		Where("family_id = ?", refresh.FamilyID).
		Order("sequence ASC").
		Find(&existing).Error; err != nil {
		return fmt.Errorf("read refresh token family: %w", err)
	}
	if len(existing) == 0 {
		if refresh.Sequence != 0 {
			return fmt.Errorf("%w: initial refresh sequence = %d, want 0", ErrInvalidArgument, refresh.Sequence)
		}
		return nil
	}

	latest := existing[len(existing)-1]
	for _, token := range existing {
		if token.RevokedAt == nil {
			return fmt.Errorf("%w: token family already has an active refresh token", ErrInvalidArgument)
		}
	}
	if refresh.ClientID != latest.ClientID || refresh.UserID != latest.UserID || !sameScopes(refresh.Scopes, latest.Scopes) {
		return fmt.Errorf("%w: token pair does not match existing family", ErrInvalidArgument)
	}
	if refresh.Sequence != latest.Sequence+1 {
		return fmt.Errorf("%w: refresh sequence = %d, want %d", ErrInvalidArgument, refresh.Sequence, latest.Sequence+1)
	}
	return nil
}

func validateTokenPair(access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) error {
	if access == nil || refresh == nil {
		return fmt.Errorf("%w: create token pair requires access and refresh tokens", ErrInvalidArgument)
	}
	if access.FamilyID == nil || *access.FamilyID != refresh.FamilyID {
		return fmt.Errorf("%w: create token pair family IDs do not match", ErrInvalidArgument)
	}
	if access.ClientID != refresh.ClientID {
		return fmt.Errorf("%w: create token pair client IDs do not match", ErrInvalidArgument)
	}
	if access.UserID != refresh.UserID {
		return fmt.Errorf("%w: create token pair user IDs do not match", ErrInvalidArgument)
	}
	if !sameScopes(access.Scopes, refresh.Scopes) {
		return fmt.Errorf("%w: create token pair scopes do not match", ErrInvalidArgument)
	}
	return nil
}

func sameScopes(left model.StringArray, right model.StringArray) bool {
	return reflect.DeepEqual([]string(left), []string(right))
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

// FindAccessTokenByJTI finds access-token metadata by its JWT ID.
func (r *TokenRepository) FindAccessTokenByJTI(
	ctx context.Context,
	jti string,
) (*model.OAuthAccessToken, error) {
	var access model.OAuthAccessToken
	err := r.database.WithContext(ctx).Where("token_id = ?", jti).First(&access).Error
	if err == nil {
		return &access, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find access token by JTI: %w", err)
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
		return revokeFamilyInTransaction(transaction, familyID, revokedAt)
	})
}

func revokeFamilyInTransaction(transaction *gorm.DB, familyID string, revokedAt time.Time) error {
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
}
