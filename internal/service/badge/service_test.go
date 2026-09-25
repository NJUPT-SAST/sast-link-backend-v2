package badge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func TestEnableCreatesBadgeWithCapabilityKey(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: nicknameCard("张三")}}
	badges := newFakeBadgeRepository()
	audits := &fakeAuditRepository{}
	service := newTestService(users, badges, audits)

	status, err := service.Enable(context.Background(), EnableInput{UserID: 7})
	if err != nil {
		t.Fatalf("Enable error = %v", err)
	}
	if !status.Enabled || status.Key == "" {
		t.Fatalf("status = %#v, want enabled with a key", status)
	}
	// 32 bytes → 43 base64url characters, URL-safe alphabet only.
	if len(status.Key) != 43 {
		t.Fatalf("key length = %d, want 43", len(status.Key))
	}
	if strings.ContainsAny(status.Key, "+/=") {
		t.Fatalf("key %q contains non-URL-safe base64 characters", status.Key)
	}

	entry := audits.last(t)
	if entry.Action != "badge_enable" || entry.Resource != "badge" {
		t.Fatalf("audit = %s/%s, want badge_enable/badge", entry.Action, entry.Resource)
	}
	if entry.ResourceID == nil || *entry.ResourceID != status.Key {
		t.Fatalf("audit resource id = %v, want the badge key", entry.ResourceID)
	}
	if entry.ActorClientID == nil || *entry.ActorClientID != "sast-link-web" {
		t.Fatalf("audit actor client = %v, want the internal client", entry.ActorClientID)
	}
}

func TestEnableKeysAreUniquePerCall(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: nicknameCard("张三")}}
	service := newTestService(users, newFakeBadgeRepository(), &fakeAuditRepository{})

	keys := make(map[string]bool)
	for i := 0; i < 64; i++ {
		// Each iteration stands in for a fresh enable after a disable, so the
		// fake starts empty.
		service.Badges = newFakeBadgeRepository()
		status, err := service.Enable(context.Background(), EnableInput{UserID: 7})
		if err != nil {
			t.Fatalf("Enable #%d error = %v", i, err)
		}
		if keys[status.Key] {
			t.Fatalf("Enable #%d reused key %q", i, status.Key)
		}
		keys[status.Key] = true
	}
}

func TestEnableRefusesMissingNickname(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: {}}}
	service := newTestService(users, newFakeBadgeRepository(), &fakeAuditRepository{})

	_, err := service.Enable(context.Background(), EnableInput{UserID: 7})
	if !errors.Is(err, ErrNicknameMissing) {
		t.Fatalf("Enable error = %v, want ErrNicknameMissing", err)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != errcode.CodeBadgeNicknameMissing {
		t.Fatalf("error code = %v, want %d", err, errcode.CodeBadgeNicknameMissing)
	}
	if !typed.Display {
		t.Fatalf("nickname-missing message should be user-facing")
	}
}

func TestEnableRefusesUnknownUser(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{}}
	service := newTestService(users, newFakeBadgeRepository(), &fakeAuditRepository{})

	_, err := service.Enable(context.Background(), EnableInput{UserID: 99})
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("Enable error = %v, want ErrUserNotFound", err)
	}
	if _, err := service.Enable(context.Background(), EnableInput{UserID: 0}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("Enable(0) error = %v, want ErrUserNotFound", err)
	}
}

func TestEnableRefusesSecondBadge(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: nicknameCard("张三")}}
	service := newTestService(users, newFakeBadgeRepository(), &fakeAuditRepository{})

	if _, err := service.Enable(context.Background(), EnableInput{UserID: 7}); err != nil {
		t.Fatalf("first Enable error = %v", err)
	}
	_, err := service.Enable(context.Background(), EnableInput{UserID: 7})
	if !errors.Is(err, ErrAlreadyEnabled) {
		t.Fatalf("second Enable error = %v, want ErrAlreadyEnabled", err)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != errcode.CodeBadgeAlreadyEnabled {
		t.Fatalf("error code = %v, want %d", err, errcode.CodeBadgeAlreadyEnabled)
	}
}

func TestDisableIsIdempotentAndAuditsOnlyRealChanges(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: nicknameCard("张三")}}
	badges := newFakeBadgeRepository()
	audits := &fakeAuditRepository{}
	service := newTestService(users, badges, audits)

	if _, err := service.Enable(context.Background(), EnableInput{UserID: 7}); err != nil {
		t.Fatalf("Enable error = %v", err)
	}
	enableEntries := len(audits.entries)

	if err := service.Disable(context.Background(), DisableInput{UserID: 7}); err != nil {
		t.Fatalf("Disable error = %v", err)
	}
	if entry := audits.last(t); entry.Action != "badge_disable" {
		t.Fatalf("audit action = %s, want badge_disable", entry.Action)
	}

	// Disabling again succeeds without a second audit row: nothing happened.
	if err := service.Disable(context.Background(), DisableInput{UserID: 7}); err != nil {
		t.Fatalf("second Disable error = %v", err)
	}
	if got := len(audits.entries); got != enableEntries+1 {
		t.Fatalf("audit entries = %d, want %d", got, enableEntries+1)
	}

	// The status is back to disabled — the row survives, hidden.
	status, err := service.Status(context.Background(), 7)
	if err != nil {
		t.Fatalf("Status error = %v", err)
	}
	if status.Enabled || status.Key != "" {
		t.Fatalf("status after disable = %#v, want disabled without key", status)
	}

	// ...and re-enabling restores the SAME key: toggling never rotates it, so
	// a saved embed URL recovers as-is.
	first, err := service.Enable(context.Background(), EnableInput{UserID: 7})
	if err != nil {
		t.Fatalf("re-enable error = %v", err)
	}
	if err := service.Disable(context.Background(), DisableInput{UserID: 7}); err != nil {
		t.Fatalf("Disable error = %v", err)
	}
	second, secondErr := service.Enable(context.Background(), EnableInput{UserID: 7})
	if secondErr != nil {
		t.Fatalf("second re-enable error = %v", secondErr)
	}
	if first.Key != second.Key {
		t.Fatalf("re-enabled key = %q, want the original %q", second.Key, first.Key)
	}
}

func TestReEnabledKeyServesTheBadgeAgain(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: {Nickname: strPtr("张三")}}}
	badges := newFakeBadgeRepository()
	service := newTestService(users, badges, &fakeAuditRepository{})

	first, err := service.Enable(context.Background(), EnableInput{UserID: 7})
	if err != nil {
		t.Fatalf("Enable error = %v", err)
	}
	disableErr := service.Disable(context.Background(), DisableInput{UserID: 7})
	if disableErr != nil {
		t.Fatalf("Disable error = %v", disableErr)
	}

	// While paused the key renders the closed card.
	paused, err := service.Render(context.Background(), RenderInput{Key: first.Key, Size: "md", Theme: "auto"})
	if err != nil {
		t.Fatalf("paused Render error = %v", err)
	}
	if !paused.NotFound {
		t.Fatalf("paused badge must render the closed card")
	}

	// The resume must also clear the cached 404 — the same request then
	// serves the badge again under the same key.
	_, resumeErr := service.Enable(context.Background(), EnableInput{UserID: 7})
	if resumeErr != nil {
		t.Fatalf("re-enable error = %v", resumeErr)
	}
	resumed, err := service.Render(context.Background(), RenderInput{Key: first.Key, Size: "md", Theme: "auto"})
	if err != nil {
		t.Fatalf("resumed Render error = %v", err)
	}
	if resumed.NotFound {
		t.Fatalf("resumed badge still renders the closed card: cached 404 not purged")
	}
}

func TestStatusUnknownUserIsNotEnabled(t *testing.T) {
	service := newTestService(&fakeUserRepository{cards: map[int64]*repository.PublicCard{}}, newFakeBadgeRepository(), &fakeAuditRepository{})

	status, err := service.Status(context.Background(), 99)
	if err != nil {
		t.Fatalf("Status(unknown) error = %v, want nil", err)
	}
	if status.Enabled {
		t.Fatalf("Status(unknown) = %#v, want disabled", status)
	}
}

// fakeLimiter records Allow calls and enforces a canned decision.
type fakeLimiter struct {
	calls   int
	allowed bool
	retry   time.Duration
	failure error
}

func (f *fakeLimiter) Allow(context.Context, string, string) (LimitResult, error) {
	f.calls++
	return LimitResult{Allowed: f.allowed, RetryAfter: f.retry}, f.failure
}

func TestEnableHonorsToggleLimiter(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: nicknameCard("张三")}}
	limiter := &fakeLimiter{allowed: false, retry: 30 * time.Second}
	service := newTestService(users, newFakeBadgeRepository(), &fakeAuditRepository{})
	service.ToggleLimiter = limiter

	_, err := service.Enable(context.Background(), EnableInput{UserID: 7})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Enable error = %v, want ErrRateLimited", err)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.RetryAfter != 30*time.Second {
		t.Fatalf("RetryAfter = %v, want 30s", typed.RetryAfter)
	}
	if limiter.calls != 1 {
		t.Fatalf("limiter calls = %d, want 1", limiter.calls)
	}
	// The cap fires before any repository write.
	if status, _ := service.Status(context.Background(), 7); status.Enabled {
		t.Fatalf("badge enabled despite the limiter refusal")
	}
}

func TestToggleLimiterFailureFailsOpen(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: nicknameCard("张三")}}
	limiter := &fakeLimiter{allowed: true, failure: errors.New("redis down")}
	service := newTestService(users, newFakeBadgeRepository(), &fakeAuditRepository{})
	service.ToggleLimiter = limiter

	status, err := service.Enable(context.Background(), EnableInput{UserID: 7})
	if err != nil || !status.Enabled {
		t.Fatalf("Enable with a broken limiter = (%v, %v), want success", status, err)
	}
}
