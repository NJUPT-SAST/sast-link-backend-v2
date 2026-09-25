package badge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

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
	// ToggleLimiter throttles the enable/disable endpoints per user, keying on
	// the authenticated subject rather than the IP: every accepted toggle
	// writes an audit row, so the cap bounds audit spam. Nil disables the
	// check (tests).
	ToggleLimiter EndpointLimiter
	// PublicLimiter throttles the unauthenticated render endpoint per IP.
	// Nil disables the check (tests).
	PublicLimiter EndpointLimiter
	// renderCache absorbs render bursts. Lazily initialized in Render so a
	// service constructed without one (older tests) still works.
	renderCacheOnce sync.Once
	renderCache     *renderCache
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

// Enable starts sharing the caller's badge and returns its key. The key is
// minted exactly once — on the first enable; a later enable after a pause
// resumes the same key, so a saved embed URL recovers as-is. It refuses a
// profile without a nickname (the badge's identity anchor) and an account
// that is already sharing — the client shows the existing badge rather than
// retrying. A user id that resolves to no live account is ErrUserNotFound,
// the same folding FindPublicCardByUserID applies.
func (s *Service) Enable(ctx context.Context, input EnableInput) (*Status, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrUserNotFound, "enable badge: non-positive user id", nil)
	}
	if err := s.checkLimit(ctx, "badge_toggle", input.UserID); err != nil {
		return nil, err
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

	enabledAt := s.Clock.Now()
	key, err := generateBadgeKey()
	if err != nil {
		return nil, newError(ErrInternal, "enable badge: generate key", err)
	}
	badge := &model.Badge{UserID: input.UserID, BadgeKey: key, EnabledAt: enabledAt}
	if err := s.Badges.Create(ctx, badge); err != nil {
		if !errors.Is(err, repository.ErrBadgeAlreadyEnabled) {
			return nil, newError(ErrInternal, "enable badge: create row", err)
		}
		// The row already exists. If it is sharing, this is the 40907 case;
		// if it is paused, resume it — keeping the key, so a saved embed URL
		// recovers as-is instead of pointing at a forever-dead link.
		existing, findErr := s.Badges.FindByUserID(ctx, input.UserID)
		if findErr != nil {
			return nil, newError(ErrInternal, "enable badge: load existing row", findErr)
		}
		if existing.DisabledAt == nil {
			return nil, newError(ErrAlreadyEnabled, "enable badge: badge already enabled", err)
		}
		resumed, reEnableErr := s.Badges.ReEnable(ctx, input.UserID, enabledAt)
		if reEnableErr != nil {
			return nil, newError(ErrInternal, "enable badge: resume row", reEnableErr)
		}
		if !resumed {
			// A concurrent enable won the resume; the badge is sharing now.
			return nil, newError(ErrAlreadyEnabled, "enable badge: badge already enabled", nil)
		}
		// The cache may still hold the paused 404 card for this key — drop it
		// so the badge recovers immediately.
		s.purgeRenderCache(existing.BadgeKey)
		s.audit(ctx, input.UserID, input.ActorClientID, "badge_enable", existing.BadgeKey, true, 0)
		return &Status{Enabled: true, Key: existing.BadgeKey, EnabledAt: &enabledAt}, nil
	}

	s.audit(ctx, input.UserID, input.ActorClientID, "badge_enable", key, true, 0)
	return &Status{Enabled: true, Key: key, EnabledAt: &enabledAt}, nil
}

// Disable pauses sharing on the caller's badge, keeping the key: the embed
// URL starts rendering the neutral "closed" card and recovers as-is when
// the owner switches back on. Disabling a badge that is already paused (or
// absent) is a success — the observable end state is the same — but no audit
// row is written when nothing changed. A real pause also purges the render
// cache for that key: without the purge, every embed keeps serving the
// cached SVG until the TTL expires, and “关闭后链接立即失效” would be a
// lie for up to five minutes.
func (s *Service) Disable(ctx context.Context, input DisableInput) error {
	if input.UserID <= 0 {
		return newError(ErrUserNotFound, "disable badge: non-positive user id", nil)
	}
	if err := s.checkLimit(ctx, "badge_toggle", input.UserID); err != nil {
		return err
	}

	existing, findErr := s.Badges.FindByUserID(ctx, input.UserID)
	if findErr != nil {
		if errors.Is(findErr, repository.ErrNotFound) {
			return nil
		}
		return newError(ErrInternal, "disable badge: find row", findErr)
	}
	if existing.DisabledAt != nil {
		// Already paused — the end state is unchanged.
		return nil
	}

	paused, err := s.Badges.Disable(ctx, input.UserID, s.Clock.Now())
	if err != nil {
		return newError(ErrInternal, "disable badge: pause row", err)
	}
	if !paused {
		// A concurrent disable won the pause; the end state is what we want.
		return nil
	}

	s.purgeRenderCache(existing.BadgeKey)
	s.audit(ctx, input.UserID, input.ActorClientID, "badge_disable", existing.BadgeKey, true, 0)
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
	if badge.DisabledAt != nil {
		// The row survives the pause, but the sharing state is off.
		return &Status{Enabled: false}, nil
	}
	enabledAt := badge.EnabledAt
	return &Status{Enabled: true, Key: badge.BadgeKey, EnabledAt: &enabledAt}, nil
}

// purgeRenderCache lazily initializes and clears the render cache for one
// badge key.
func (s *Service) purgeRenderCache(badgeKey string) {
	s.renderCacheOnce.Do(func() {
		if s.renderCache == nil {
			s.renderCache = newRenderCache()
		}
	})
	s.renderCache.purge(badgeKey)
}

// checkLimit applies the per-user toggle cap. A limiter failure is logged and
// the request allowed: the badge endpoints are self-service surface, and a
// Redis blip must not lock users out of their own settings.
func (s *Service) checkLimit(ctx context.Context, endpoint string, userID int64) error {
	if s.ToggleLimiter == nil {
		return nil
	}
	result, err := s.ToggleLimiter.Allow(ctx, endpoint, strconv.FormatInt(userID, 10))
	if err != nil {
		slog.WarnContext(ctx, "badge limiter unavailable, allowing request", "error", err)
		return nil
	}
	if !result.Allowed {
		return withRetryAfter(newError(ErrRateLimited, "badge toggle rate limited", nil), result.RetryAfter)
	}
	return nil
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
