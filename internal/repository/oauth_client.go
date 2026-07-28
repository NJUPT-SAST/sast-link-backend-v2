package repository

import (
	"context"
	"errors"
	"fmt"

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

// FindByID finds an OAuth client by its primary key, regardless of active state.
//
// Token and revoke requests arrive carrying a public client_id but must be
// matched against the client_id stored on existing token rows, which is this
// primary key. Deactivating a client must not turn its live tokens into rows
// whose owner cannot be resolved, so this lookup deliberately ignores is_active;
// callers that need to reject a disabled client check IsActive themselves.
func (r *OAuthClientRepository) FindByID(ctx context.Context, id int64) (*model.OAuthClient, error) {
	if id <= 0 {
		return nil, fmt.Errorf("%w: client primary key is not positive", ErrInvalidArgument)
	}

	var client model.OAuthClient
	err := r.database.WithContext(ctx).First(&client, id).Error
	if err == nil {
		return &client, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find OAuth client by ID: %w", err)
}
