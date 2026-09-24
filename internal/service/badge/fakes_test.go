package badge

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// fakeUserRepository serves FindPublicCardByUserID from a canned map.
type fakeUserRepository struct {
	mu    sync.Mutex
	cards map[int64]*repository.PublicCard
}

func (f *fakeUserRepository) FindPublicCardByUserID(_ context.Context, userID int64) (*repository.PublicCard, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if card, ok := f.cards[userID]; ok {
		return card, nil
	}
	return nil, repository.ErrNotFound
}

// fakeBadgeRepository mirrors the row semantics: one row per user.
type fakeBadgeRepository struct {
	mu   sync.Mutex
	rows map[int64]*model.Badge
}

func newFakeBadgeRepository() *fakeBadgeRepository {
	return &fakeBadgeRepository{rows: make(map[int64]*model.Badge)}
}

func (f *fakeBadgeRepository) Create(_ context.Context, badge *model.Badge) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.rows[badge.UserID]; exists {
		return repository.ErrBadgeAlreadyEnabled
	}
	stored := *badge
	f.rows[badge.UserID] = &stored
	return nil
}

func (f *fakeBadgeRepository) FindByUserID(_ context.Context, userID int64) (*model.Badge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if row, ok := f.rows[userID]; ok {
		stored := *row
		return &stored, nil
	}
	return nil, repository.ErrNotFound
}

func (f *fakeBadgeRepository) FindBadgeTarget(_ context.Context, badgeKey string) (*model.Badge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, row := range f.rows {
		if row.BadgeKey == badgeKey {
			stored := *row
			return &stored, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (f *fakeBadgeRepository) DeleteByUserID(_ context.Context, userID int64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.rows[userID]; !ok {
		return false, nil
	}
	delete(f.rows, userID)
	return true, nil
}

// fakeAuditRepository records audit entries in order.
type fakeAuditRepository struct {
	mu      sync.Mutex
	entries []model.AuditLog
}

func (f *fakeAuditRepository) Create(_ context.Context, entry *model.AuditLog) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, *entry)
	return nil
}

func (f *fakeAuditRepository) last(t testing.TB) model.AuditLog {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.entries) == 0 {
		t.Fatalf("no audit entries recorded")
	}
	return f.entries[len(f.entries)-1]
}

// stubClock returns a fixed time so audit timestamps and EnabledAt are
// deterministic in assertions.
type stubClock struct {
	fixed time.Time
}

func (c stubClock) Now() time.Time { return c.fixed }

// newTestService wires the service over the fakes with sensible defaults.
func newTestService(users *fakeUserRepository, badges *fakeBadgeRepository, audits *fakeAuditRepository) *Service {
	return &Service{
		Users:            users,
		Badges:           badges,
		Audits:           audits,
		Clock:            stubClock{fixed: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)},
		InternalClientID: "sast-link-web",
	}
}

func nicknameCard(nickname string) *repository.PublicCard {
	return &repository.PublicCard{Nickname: &nickname}
}
