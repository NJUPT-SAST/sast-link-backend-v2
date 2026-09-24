package badge

import (
	"context"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// UserRepository is the surface of repository.UserRepository this service
// needs: the public-card projection is both the enable-time nickname check
// and (later) the render source, so the badge reads exactly the columns the
// card exposes and cannot widen the surface.
type UserRepository interface {
	FindPublicCardByUserID(ctx context.Context, userID int64) (*repository.PublicCard, error)
}

// BadgeRepository is the surface of repository.BadgeRepository this service
// needs.
type BadgeRepository interface {
	Create(ctx context.Context, badge *model.Badge) error
	FindByUserID(ctx context.Context, userID int64) (*model.Badge, error)
	DeleteByUserID(ctx context.Context, userID int64) (bool, error)
}

// AuditRepository is the surface of repository.AuditLogRepository this
// service needs.
type AuditRepository interface {
	Create(ctx context.Context, entry *model.AuditLog) error
}

// Status is the answer to GET /user/badge: the badge's sharing state. Key is
// present only while the badge is enabled — the share URL is derived from it
// by the client, which knows the public API base this deployment runs behind.
type Status struct {
	Enabled   bool      `json:"enabled"`
	Key       string    `json:"key,omitempty"`
	EnabledAt time.Time `json:"enabled_at,omitempty"`
}
