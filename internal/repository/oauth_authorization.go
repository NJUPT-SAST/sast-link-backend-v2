package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// ErrAuthorizationReplayed reports that an authorization code was presented more
// than once. The caller must treat this as an attack and revoke the whole token
// family named by the returned code, per PRD §4.10.
var ErrAuthorizationReplayed = errors.New("repository: authorization code replayed")

// ErrAuthorizationExpired reports an authorization code past its expires_at.
var ErrAuthorizationExpired = errors.New("repository: authorization code expired")

// OAuthAuthorizationRepository persists single-use OAuth authorization codes.
type OAuthAuthorizationRepository struct {
	database *gorm.DB
}

// NewOAuthAuthorization constructs an OAuthAuthorizationRepository.
func NewOAuthAuthorization(database *gorm.DB) *OAuthAuthorizationRepository {
	return &OAuthAuthorizationRepository{database: database}
}

// Create persists a new authorization code.
func (r *OAuthAuthorizationRepository) Create(ctx context.Context, authorization *model.OAuthAuthorization) error {
	if authorization == nil || strings.TrimSpace(authorization.Code) == "" ||
		authorization.ClientID <= 0 || authorization.UserID <= 0 {
		return fmt.Errorf("create authorization: %w", ErrInvalidArgument)
	}
	if err := r.database.WithContext(ctx).Create(authorization).Error; err != nil {
		return fmt.Errorf("create authorization: %w", err)
	}
	return nil
}

// Consume atomically marks an authorization code used and returns it.
//
// The row is locked before is_used is inspected, so two token requests carrying
// the same code serialize here rather than both passing the check: the loser sees
// is_used already TRUE and gets ErrAuthorizationReplayed. Doing this as a bare
// read-then-update would let both requests mint a token pair from one code.
//
// On replay the record is still returned alongside the error, because the caller
// needs its family_id to cascade the revocation. Expiry is reported separately
// and does not mark the code used — an expired code was never redeemed, so there
// is no family to punish.
func (r *OAuthAuthorizationRepository) Consume(
	ctx context.Context,
	code string,
	now time.Time,
) (*model.OAuthAuthorization, error) {
	if strings.TrimSpace(code) == "" || now.IsZero() {
		return nil, fmt.Errorf("consume authorization: %w", ErrInvalidArgument)
	}
	var authorization model.OAuthAuthorization
	var replayed bool
	var expired bool
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		lockErr := transaction.
			Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("code = ?", code).
			First(&authorization).Error
		if errors.Is(lockErr, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		if lockErr != nil {
			return fmt.Errorf("lock authorization: %w", lockErr)
		}
		if authorization.IsUsed {
			replayed = true
			return nil
		}
		if !authorization.ExpiresAt.After(now) {
			expired = true
			return nil
		}
		result := transaction.Model(&model.OAuthAuthorization{}).
			Where("id = ? AND is_used = FALSE", authorization.ID).
			Update("is_used", true)
		if result.Error != nil {
			return fmt.Errorf("mark authorization used: %w", result.Error)
		}
		if result.RowsAffected != 1 {
			// The row was locked above, so losing this update means the lock did not
			// hold. Report a replay rather than issuing tokens from a code whose
			// single-use guarantee just failed.
			replayed = true
			return nil
		}
		authorization.IsUsed = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if replayed {
		return &authorization, ErrAuthorizationReplayed
	}
	if expired {
		return &authorization, ErrAuthorizationExpired
	}
	return &authorization, nil
}
