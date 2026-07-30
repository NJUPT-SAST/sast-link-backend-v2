package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// OAuthClientRepository retrieves registered OAuth clients.
type OAuthClientRepository struct {
	database *gorm.DB
}

// NewOAuthClient constructs an OAuthClientRepository backed by database.
func NewOAuthClient(database *gorm.DB) *OAuthClientRepository {
	return &OAuthClientRepository{database: database}
}

// FindActiveByClientID finds an active OAuth client by its public client_id.
func (r *OAuthClientRepository) FindActiveByClientID(ctx context.Context, clientID string) (*model.OAuthClient, error) {
	if clientID == "" {
		return nil, fmt.Errorf("%w: client ID is empty", ErrInvalidArgument)
	}

	var client model.OAuthClient
	err := r.database.WithContext(ctx).
		Where("client_id = ? AND is_active = TRUE", clientID).
		First(&client).Error
	if err == nil {
		return &client, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find active OAuth client by client ID: %w", err)
}

// FindByID finds a client by primary key regardless of active state.
//
// The admin update path needs the current row to decide whether is_active is
// transitioning from true to false, which is what triggers token revocation. It
// must therefore see disabled clients too.
func (r *OAuthClientRepository) FindByID(ctx context.Context, id int64) (*model.OAuthClient, error) {
	if id <= 0 {
		return nil, fmt.Errorf("%w: client ID must be positive", ErrInvalidArgument)
	}
	var client model.OAuthClient
	err := r.database.WithContext(ctx).Where("id = ?", id).First(&client).Error
	if err == nil {
		return &client, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find OAuth client by ID: %w", err)
}

// List returns every registered client, disabled ones included, ordered by ID.
//
// Deliberately unpaginated: the documented response (API 文档 §6.6) carries no
// total/page fields, unlike the user list, because client registrations are an
// administrative handful rather than an open-ended collection.
func (r *OAuthClientRepository) List(ctx context.Context) ([]model.OAuthClient, error) {
	var clients []model.OAuthClient
	if err := r.database.WithContext(ctx).Order("id").Find(&clients).Error; err != nil {
		return nil, fmt.Errorf("list OAuth clients: %w", err)
	}
	return clients, nil
}

// Create inserts a new client registration.
func (r *OAuthClientRepository) Create(ctx context.Context, client *model.OAuthClient) error {
	if client == nil {
		return fmt.Errorf("%w: client is nil", ErrInvalidArgument)
	}
	if err := r.database.WithContext(ctx).Create(client).Error; err != nil {
		return fmt.Errorf("create OAuth client: %w", err)
	}
	return nil
}

// UpdateAndRevoke applies fields to a client and, when revokeTokens is set,
// revokes every live token issued to it in the same transaction.
//
// Atomicity is the point. Disabling a client is a security action and an
// administrator expects it to cut access immediately, so the flag flip and the
// revocation must not be separable: committing the flag while the revocation fails
// would leave live tokens behind a client the console reports as disabled. The
// returned entries are the still-live access JTIs needing blacklist delivery;
// their durable outbox rows are written here, so a later delivery failure only
// delays the fast-reject path.
//
// Returns ErrNotFound when the client does not exist.
func (r *OAuthClientRepository) UpdateAndRevoke(
	ctx context.Context,
	id int64,
	fields map[string]any,
	revokeTokens bool,
	revokedAt time.Time,
) ([]model.BlacklistEntry, error) {
	if id <= 0 {
		return nil, fmt.Errorf("%w: client ID must be positive", ErrInvalidArgument)
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("%w: no fields to update", ErrInvalidArgument)
	}
	var entries []model.BlacklistEntry
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		result := transaction.Model(&model.OAuthClient{}).Where("id = ?", id).Updates(fields)
		if result.Error != nil {
			return fmt.Errorf("update OAuth client: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return ErrNotFound
		}
		if !revokeTokens {
			return nil
		}
		revoked, revokeErr := revokeAllByClientInTransaction(transaction, id, revokedAt)
		if revokeErr != nil {
			return revokeErr
		}
		entries = revoked
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}
