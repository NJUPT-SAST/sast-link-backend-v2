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
// lifetime. It is safe to cache unconditionally: the internal client is
// first-party-public and immutable — admin updates exclude its scope, grant
// types, secret and active state — so no invalidation is ever needed. Third-party
// clients must NOT use this cache (they can be disabled or rescoped live).
var internalClientCache sync.Map // clientID -> *model.OAuthClient

// FindActiveInternalClient finds the built-in first-party client, serving it from
// a process-local cache after the first load. Every login/refresh/exchange-code
// resolves it, so this removes one DB round trip from each without any staleness
// risk. Only call it for the internal client.
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

// ResetInternalClientCache clears the cached built-in client. The cache is
// process-global, so an integration test that seeds the internal client after a
// previous test cached it would otherwise read a stale fixture; call this in
// test setup. Production never needs it — the internal client is immutable.
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
// returned entries are the still-live access JTIs needing revocation delivery;
// their durable outbox rows are written here, so a later delivery failure only
// delays the fast-reject path. revokedRefresh is the count of unrevoked refresh
// tokens that were revoked, so a disable that only cuts a live refresh session
// still reports it — same reporting contract as DeleteAndRevoke.
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
// Deleting a registration is a "cut access now" action one step past disabling:
// the ON DELETE CASCADE foreign keys wipe the client's authorization codes and
// access/refresh token metadata, and the revocation leg here guarantees the
// still-live access JTIs are enqueued for blacklist delivery (and auth-state
// cache invalidation) before the row disappears — the cache would otherwise keep
// admitting a token whose authoritative DB row is gone. The returned entries are
// the still-live access JTIs needing that delivery, and revokedRefresh is the
// count of unrevoked refresh tokens that were revoked — accurate because every
// family holds exactly one unrevoked refresh token at a time, so a client that
// only holds a live refresh session still reports that its sessions were cut.
//
// The revocation runs before the delete on purpose: once the row is gone the
// CASCADE would have emptied the access-token table, and the SELECT that feeds
// the outbox would find nothing to enqueue. Returns ErrNotFound when the client
// does not exist; the row is deleted only if the revocation leg succeeded, so a
// partial failure cannot leave live tokens behind a client the console reports
// as gone.
//
// A token minted by a concurrent redeem/refresh that commits between the
// revocation leg and the delete escapes the outbox and is then CASCADE-removed.
// It can only outlive the delete if it was already used (its auth-state blob
// cached) before the delete committed and the tombstone landed — a sub-millisecond
// double race, and its own blob TTL bounds it; accepted without a re-check.
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
