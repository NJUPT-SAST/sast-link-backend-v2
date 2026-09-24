package badge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/shared"
)

// badgeKeyBytes is the entropy behind a badge URL: 32 random bytes,
// base64url-encoded to 43 characters. The value is a capability — possession
// of the URL is the credential to view — so 256 bits keeps brute force and
// enumeration out of reach of the per-IP rate limiter's budget.
const badgeKeyBytes = 32

// Service implements the personal-badge lifecycle. Dependencies are exported
// fields assembled in cmd/api, matching the session and oauthlogin services.
type Service struct {
	Users  UserRepository
	Badges BadgeRepository
	Audits AuditRepository
	Clock  auth.Clock
	// InternalClientID names the built-in first-party client that owns
	// console-issued sessions; an empty ActorClientID on an input resolves to
	// it at audit time, mirroring the session service.
	InternalClientID string
}

// EnableInput carries the enable call's subject and authorizer.
type EnableInput struct {
	UserID int64
	// ActorClientID is the azp of the token that authorized the call; empty
	// means a legacy console token, resolved to InternalClientID at audit time.
	ActorClientID string
}

// DisableInput carries the disable call's subject and authorizer.
type DisableInput struct {
	UserID        int64
	ActorClientID string
}

// Enable creates the caller's badge row and returns its key. It refuses a
// profile without a nickname (the badge's identity anchor) and an account
// that already holds a badge — the client shows the existing badge rather
// than retrying. A user id that resolves to no live account is
// ErrUserNotFound, the same folding FindPublicCardByUserID applies.
func (s *Service) Enable(ctx context.Context, input EnableInput) (*Status, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrUserNotFound, "enable badge: non-positive user id", nil)
	}

	card, err := s.Users.FindPublicCardByUserID(ctx, input.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, newError(ErrUserNotFound, "enable badge: user not found", err)
		}
		return nil, newError(ErrInternal, "enable badge: load public card", err)
	}
	if card.Nickname == nil || strings.TrimSpace(*card.Nickname) == "" {
		return nil, newError(ErrNicknameMissing, "enable badge: profile has no nickname", nil)
	}

	key, err := generateBadgeKey()
	if err != nil {
		return nil, newError(ErrInternal, "enable badge: generate key", err)
	}
	enabledAt := s.Clock.Now()
	badge := &model.Badge{UserID: input.UserID, BadgeKey: key, EnabledAt: enabledAt}
	if err := s.Badges.Create(ctx, badge); err != nil {
		if errors.Is(err, repository.ErrBadgeAlreadyEnabled) {
			return nil, newError(ErrAlreadyEnabled, "enable badge: badge already enabled", err)
		}
		return nil, newError(ErrInternal, "enable badge: create row", err)
	}

	s.audit(ctx, input.UserID, input.ActorClientID, "badge_enable", key, true, 0)
	return &Status{Enabled: true, Key: key, EnabledAt: enabledAt}, nil
}

// Disable removes the caller's badge row. Disabling a badge that is not
// enabled is a success — the observable end state is the same — but no audit
// row is written when nothing was removed.
func (s *Service) Disable(ctx context.Context, input DisableInput) error {
	if input.UserID <= 0 {
		return newError(ErrUserNotFound, "disable badge: non-positive user id", nil)
	}

	removed, err := s.Badges.DeleteByUserID(ctx, input.UserID)
	if err != nil {
		return newError(ErrInternal, "disable badge: delete row", err)
	}
	if !removed {
		return nil
	}

	s.audit(ctx, input.UserID, input.ActorClientID, "badge_disable", "", true, 0)
	return nil
}

// Status reports the caller's badge sharing state without the failure paths
// of Enable: an unknown user and a disabled badge are both "not enabled".
func (s *Service) Status(ctx context.Context, userID int64) (*Status, error) {
	if userID <= 0 {
		return nil, newError(ErrUserNotFound, "badge status: non-positive user id", nil)
	}

	badge, err := s.Badges.FindByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return &Status{Enabled: false}, nil
		}
		return nil, newError(ErrInternal, "badge status: find row", err)
	}
	return &Status{Enabled: true, Key: badge.BadgeKey, EnabledAt: badge.EnabledAt}, nil
}

// generateBadgeKey returns a fresh 43-character base64url capability key.
func generateBadgeKey() (string, error) {
	buf := make([]byte, badgeKeyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// audit writes one badge lifecycle event. Audit failures are logged, not
// returned: a badge toggle must not report failure because its audit row
// could not land.
func (s *Service) audit(ctx context.Context, userID int64, actorClientID, action, badgeKey string, success bool, errCode int) {
	var errCodePtr *int
	if errCode != 0 {
		errCodePtr = &errCode
	}
	successPtr := success
	entry := &model.AuditLog{
		UserID:        &userID,
		Action:        action,
		Resource:      "badge",
		ResourceID:    &badgeKey,
		ActorClientID: shared.NullableString(shared.ActorClientID(actorClientID, s.InternalClientID)),
		Success:       &successPtr,
		ErrCode:       errCodePtr,
		CreatedAt:     s.Clock.Now(),
	}
	if err := s.Audits.Create(ctx, entry); err != nil {
		slog.ErrorContext(ctx, "badge: write audit row", "action", action, "error", err)
	}
}
