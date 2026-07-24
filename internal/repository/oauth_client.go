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
