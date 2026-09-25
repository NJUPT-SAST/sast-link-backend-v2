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

// CreateWithGrant persists a new authorization code and records the user's
// consent in oauth_grants, in one transaction: an application can never hold a
// live code without appearing in the authorized-apps list. oauth_grants is
// keyed by (user_id, client_id), so a repeated consent upserts the pair.
func (r *OAuthAuthorizationRepository) CreateWithGrant(ctx context.Context, authorization *model.OAuthAuthorization) error {
	if err := validateNewAuthorization(authorization); err != nil {
		return fmt.Errorf("create authorization with grant: %w", err)
	}
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := lockAuthorizationClient(transaction, authorization.ClientID); err != nil {
			return err
		}
		if err := transaction.Create(authorization).Error; err != nil {
			return err
		}
		// Read CreatedAt after the insert so a caller relying on GORM's
		// autoCreateTime gets the value the row actually carries. Evaluating it
		// before the insert would write the zero time (oauth_grants.granted_at is
		// NOT NULL with no DEFAULT, so V009 would accept 0001-01-01 silently).
		grant := &model.OAuthGrant{
			UserID:    authorization.UserID,
			ClientID:  authorization.ClientID,
			Scopes:    authorization.Scopes,
			GrantedAt: authorization.CreatedAt,
		}
		return transaction.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}, {Name: "client_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"scopes", "granted_at"}),
		}).Create(grant).Error
	})
	if err != nil {
		return fmt.Errorf("create authorization with grant: %w", err)
	}
	return nil
}

// CreateWithExistingGrant persists a new authorization code against a consent
// grant that must already exist, in one transaction.
//
// This is the silent-authorize path's writer, and the difference from
// CreateWithGrant is deliberately narrow: a silent code is minted on the
// strength of a standing grant, so it must never be the thing that creates that
// grant. CreateWithGrant upserts the pair, which means an in-flight silent mint
// could resurrect a grant the user revoked a millisecond earlier — the app
// reappears in the authorized-apps list and the client holds a live code, so the
// revoke's promise ("the client must consent again") is silently undone.
// Grant revocation deletes the grants and codes that exist when it runs, and
// cannot delete a row a later transaction re-inserts.
//
// Ordering the grant write first, as an UPDATE, closes that: the row lock
// serializes this transaction against the revoking DELETE, and if the delete
// committed first there is nothing to update, RowsAffected is 0, and returning
// ErrNotFound rolls back the code insert with the rest of the transaction. No
// grant row, no code. The scope predicate is rechecked under the same row
// lock, so a concurrent interactive scope reduction cannot be overwritten.
// Zero affected rows means the grant is absent or no longer covers the request.
func (r *OAuthAuthorizationRepository) CreateWithExistingGrant(ctx context.Context, authorization *model.OAuthAuthorization) error {
	if err := validateNewAuthorization(authorization); err != nil {
		return fmt.Errorf("create authorization with existing grant: %w", err)
	}
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := lockAuthorizationClient(transaction, authorization.ClientID); err != nil {
			return err
		}
		updated := transaction.Model(&model.OAuthGrant{}).
			Where("user_id = ? AND client_id = ? AND scopes @> ?::text[]", authorization.UserID, authorization.ClientID, authorization.Scopes).
			Updates(map[string]any{
				"scopes":     authorization.Scopes,
				"granted_at": authorization.CreatedAt,
			})
		if updated.Error != nil {
			return updated.Error
		}
		if updated.RowsAffected == 0 {
			return ErrNotFound
		}
		return transaction.Create(authorization).Error
	})
	if err != nil {
		return fmt.Errorf("create authorization with existing grant: %w", err)
	}
	return nil
}

// validateNewAuthorization rejects an authorization that cannot be persisted,
// shared by both writers so the two cannot drift on what a usable record is.
func validateNewAuthorization(authorization *model.OAuthAuthorization) error {
	if authorization == nil || strings.TrimSpace(authorization.Code) == "" ||
		authorization.ClientID <= 0 || authorization.UserID <= 0 {
		return ErrInvalidArgument
	}
	return nil
}

// Consume atomically marks an authorization code used and returns it. The row
// is locked before is_used is inspected, so two requests carrying the same code
// serialize and the loser gets ErrAuthorizationReplayed instead of minting a
// pair. On replay the record is still returned because the caller needs its
// family_id to cascade revocation; expiry is reported separately and does not
// mark the code used.
func (r *OAuthAuthorizationRepository) Consume(
	ctx context.Context,
	code string,
	now time.Time,
	clientID int64,
) (*model.OAuthAuthorization, int64, error) {
	if strings.TrimSpace(code) == "" || now.IsZero() || clientID <= 0 {
		return nil, 0, fmt.Errorf("consume authorization: %w", ErrInvalidArgument)
	}
	var authorization model.OAuthAuthorization
	var userTokenVersion int64
	var replayed bool
	var expired bool
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		lockErr := transaction.
			Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("code = ? AND client_id = ?", code, clientID).
			First(&authorization).Error
		if errors.Is(lockErr, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		if lockErr != nil {
			return fmt.Errorf("lock authorization: %w", lockErr)
		}
		if authorization.IsUsed {
			replayed = true
			// A replay may precede the first request's pair write. Expire the
			// code under its lock to fence that write, retaining the family for
			// repeated revocation attempts if downstream delivery fails.
			return transaction.Model(&authorization).
				Update("expires_at", gorm.Expr("LEAST(expires_at, ?)", now)).Error
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
		// The user's token_version rides the consume transaction as a snapshot so a
		// revocation that commits after this consume cannot be escaped by the pair
		// creation below.
		if err := transaction.Model(&model.User{}).
			Select("token_version").
			Where("id = ?", authorization.UserID).
			Scan(&userTokenVersion).Error; err != nil {
			return fmt.Errorf("read user token version: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if replayed {
		return &authorization, userTokenVersion, ErrAuthorizationReplayed
	}
	if expired {
		return &authorization, userTokenVersion, ErrAuthorizationExpired
	}
	return &authorization, userTokenVersion, nil
}

// FindGrantScopes returns the scopes of the user's standing consent with one
// client. found is false when the user has never consented (or has revoked the
// grant), which tells the caller to fall back to the consent page rather than
// treat the pair as silently authorizable.
func (r *OAuthAuthorizationRepository) FindGrantScopes(ctx context.Context, userID, clientID int64) (model.StringArray, bool, error) {
	if userID <= 0 || clientID <= 0 {
		return nil, false, fmt.Errorf("find grant scopes: %w", ErrInvalidArgument)
	}
	var grant model.OAuthGrant
	err := r.database.WithContext(ctx).
		Where("user_id = ? AND client_id = ?", userID, clientID).
		First(&grant).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("find grant scopes: %w", err)
	}
	return grant.Scopes, true, nil
}

// OAuthGrant is one application a user has authorized via the consent screen,
// with the client's display fields and the most recent authorization's scopes.
// RedirectURIs and Scopes are model.StringArray because the columns are
// PostgreSQL text[], which []string cannot scan.
type OAuthGrant struct {
	ClientID         int64             `json:"client_id"`
	ClientKey        string            `json:"client_key"`
	ClientName       string            `json:"client_name"`
	ClientType       string            `json:"client_type"`
	RedirectURIs     model.StringArray `gorm:"type:text[]" json:"redirect_uris"`
	IsActive         *bool             `json:"is_active"`
	Scopes           model.StringArray `gorm:"type:text[]" json:"scopes"`
	LastAuthorizedAt time.Time         `json:"last_authorized_at"`
}

// ListGrantsByUser returns the applications a user has authorized, one row per
// client (oauth_grants is keyed by user_id + client_id), joined with the
// client's public display fields. Scopes and the grant time come from the grant
// row, never from the client registration.
func (r *OAuthAuthorizationRepository) ListGrantsByUser(ctx context.Context, userID int64) ([]OAuthGrant, error) {
	grants := make([]OAuthGrant, 0, 8)
	err := r.database.WithContext(ctx).
		Model(&model.OAuthGrant{}).
		Select(`oauth_grants.client_id,
			oauth_clients.client_id AS client_key,
			oauth_clients.client_name,
			oauth_clients.client_type,
			oauth_clients.redirect_uris,
			oauth_clients.is_active,
			oauth_grants.scopes,
			oauth_grants.granted_at AS last_authorized_at`).
		Joins(`JOIN oauth_clients ON oauth_clients.id = oauth_grants.client_id`).
		Where(`oauth_grants.user_id = ?`, userID).
		Order(`oauth_grants.client_id`).
		Scan(&grants).Error
	if err != nil {
		return nil, fmt.Errorf("list oauth grants: %w", err)
	}
	return grants, nil
}

// deleteAuthorizationsInTransaction shares the grant -> code lock order with
// issuance. The caller must revoke tokens and persist the outbox before commit.
func deleteAuthorizationsInTransaction(transaction *gorm.DB, userID, clientID int64) error {
	if err := transaction.Where("user_id = ? AND client_id = ?", userID, clientID).
		Delete(&model.OAuthGrant{}).Error; err != nil {
		return err
	}
	return transaction.Where("user_id = ? AND client_id = ?", userID, clientID).
		Delete(&model.OAuthAuthorization{}).Error
}

// All grant/code writers share-lock the client first. Client deletion takes a
// conflicting NO KEY UPDATE lock before grant -> code -> family, preventing
// cascades from reversing that order. Readers do not serialize each other.
func lockAuthorizationClient(transaction *gorm.DB, clientID int64) error {
	var client model.OAuthClient
	err := transaction.Clauses(clause.Locking{Strength: "SHARE"}).Select("id").Where("id = ?", clientID).Take(&client).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}
