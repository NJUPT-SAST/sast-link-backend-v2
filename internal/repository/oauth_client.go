package repository

import (
	"context"
	"errors"
	"fmt"
	"sync"
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

// internalClientCache holds the validated built-in client for the process
// lifetime; it is immutable, so no invalidation is ever needed. Third-party
// clients must NOT use this cache — they can be disabled or rescoped live.
var internalClientCache sync.Map // clientID -> *model.OAuthClient

// FindActiveInternalClient finds the built-in first-party client, serving it
// from a process-local cache after the first load. Only call it for the
// internal client.
func (r *OAuthClientRepository) FindActiveInternalClient(ctx context.Context, clientID string) (*model.OAuthClient, error) {
	if cached, ok := internalClientCache.Load(clientID); ok {
		return cached.(*model.OAuthClient), nil
	}
	client, err := r.FindActiveByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	internalClientCache.Store(clientID, client)
	return client, nil
}

// ResetInternalClientCache clears the cached built-in client, for test setup
// after a previous test cached it. Production never needs it — the internal
// client is immutable.
func ResetInternalClientCache() {
	internalClientCache.Clear()
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

// FindByID finds a client by primary key regardless of active state, since the
// admin update path must see disabled clients to detect disable transitions.
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
// Deliberately unpaginated — client registrations are an administrative handful,
// not an open-ended collection.
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
// revokes every live token issued to it in the same transaction: separating the
// flag flip from the revocation would leave live tokens behind a client the
// console reports as disabled. The returned entries are the still-live access
// JTIs needing revocation delivery (their durable outbox rows are written
// here), and revokedRefresh counts the unrevoked refresh tokens cut.
//
// Returns ErrNotFound when the client does not exist.
func (r *OAuthClientRepository) UpdateAndRevoke(
	ctx context.Context,
	id int64,
	fields map[string]any,
	revokeTokens bool,
	revokedAt time.Time,
) ([]model.BlacklistEntry, int64, error) {
	if id <= 0 {
		return nil, 0, fmt.Errorf("%w: client ID must be positive", ErrInvalidArgument)
	}
	if len(fields) == 0 {
		return nil, 0, fmt.Errorf("%w: no fields to update", ErrInvalidArgument)
	}
	var entries []model.BlacklistEntry
	var revokedRefresh int64
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
		revoked, refreshed, revokeErr := revokeAllByClientInTransaction(transaction, id, revokedAt)
		if revokeErr != nil {
			return revokeErr
		}
		entries = revoked
		revokedRefresh = refreshed
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return entries, revokedRefresh, nil
}

// DeleteAndRevoke permanently removes an OAuth client and, in the same
// transaction, revokes every live token issued to it.
//
// The revocation leg runs before the delete: once the row is gone the CASCADE
// would have emptied the access-token table, so the outbox SELECT must run
// first. The row is deleted only if the revocation leg succeeded, so a partial
// failure cannot leave live tokens behind a client the console reports as gone.
// The returned entries are the still-live access JTIs needing blacklist
// delivery (and auth-state cache invalidation), and revokedRefresh counts the
// unrevoked refresh tokens cut.
//
// A token minted by a concurrent redeem/refresh that commits between the
// revocation leg and the delete escapes the outbox and is then CASCADE-removed;
// it can only outlive the delete if its auth-state blob was already cached — a
// sub-millisecond race bounded by the blob TTL, accepted without a re-check.
//
// Returns ErrNotFound when the client does not exist.
func (r *OAuthClientRepository) DeleteAndRevoke(
	ctx context.Context,
	id int64,
	revokedAt time.Time,
) ([]model.BlacklistEntry, int64, error) {
	if id <= 0 {
		return nil, 0, fmt.Errorf("%w: client ID must be positive", ErrInvalidArgument)
	}
	var entries []model.BlacklistEntry
	var revokedRefresh int64
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		revoked, refreshed, revokeErr := revokeAllByClientInTransaction(transaction, id, revokedAt)
		if revokeErr != nil {
			return revokeErr
		}
		entries = revoked
		revokedRefresh = refreshed
		result := transaction.Delete(&model.OAuthClient{}, "id = ?", id)
		if result.Error != nil {
			return fmt.Errorf("delete OAuth client: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return entries, revokedRefresh, nil
}
