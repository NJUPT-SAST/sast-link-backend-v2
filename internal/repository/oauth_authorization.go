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

// OAuthGrant is one application a user has authorized via the consent screen,
// with the client's display fields and the most recent authorization's scopes.
type OAuthGrant struct {
	ClientID         int64     `json:"client_id"`
	ClientKey        string    `json:"client_key"`
	ClientName       string    `json:"client_name"`
	ClientType       string    `json:"client_type"`
	RedirectURIs     []string  `json:"redirect_uris"`
	IsActive         *bool     `json:"is_active"`
	Scopes           []string  `json:"scopes"`
	LastAuthorizedAt time.Time `json:"last_authorized_at"`
}

// ListGrantsByUser returns the distinct applications a user has authorized,
// newest consent per client, joined with the client's public display fields.
func (r *OAuthAuthorizationRepository) ListGrantsByUser(ctx context.Context, userID int64) ([]OAuthGrant, error) {
	grants := make([]OAuthGrant, 0, 8)
	err := r.database.WithContext(ctx).
		Model(&model.OAuthAuthorization{}).
		Select(`DISTINCT ON (oauth_authorizations.client_id)
			oauth_authorizations.client_id,
			oauth_clients.client_id AS client_key,
			oauth_clients.client_name,
			oauth_clients.client_type,
			oauth_clients.redirect_uris,
			oauth_clients.is_active,
			oauth_authorizations.scopes,
			oauth_authorizations.created_at AS last_authorized_at`).
		Joins(`JOIN oauth_clients ON oauth_clients.id = oauth_authorizations.client_id`).
		Where(`oauth_authorizations.user_id = ?`, userID).
		Order(`oauth_authorizations.client_id, oauth_authorizations.created_at DESC`).
		Scan(&grants).Error
	if err != nil {
		return nil, fmt.Errorf("list oauth grants: %w", err)
	}
	return grants, nil
}

// DeleteByUserClient removes every authorization a user holds with one client,
// which drops the application from the user's authorized-apps list.
func (r *OAuthAuthorizationRepository) DeleteByUserClient(ctx context.Context, userID, clientID int64) error {
	err := r.database.WithContext(ctx).
		Where("user_id = ? AND client_id = ?", userID, clientID).
		Delete(&model.OAuthAuthorization{}).Error
	if err != nil {
		return fmt.Errorf("delete user client authorizations: %w", err)
	}
	return nil
}
