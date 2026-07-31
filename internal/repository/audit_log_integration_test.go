package repository_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func TestAuditLogRepositoryCreate(t *testing.T) {
	database := setupDatabase(t)
	auditLogRepository := repository.NewAuditLog(database)
	entry := &model.AuditLog{
		Action:   "login",
		Resource: "user",
		Detail:   model.JSONB(`{"provider":"password","success":true}`),
	}

	if err := auditLogRepository.Create(context.Background(), entry); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	var found model.AuditLog
	if err := database.First(&found, entry.ID).Error; err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if found.UserID != nil || found.Action != entry.Action || found.Resource != entry.Resource ||
		found.Success == nil || !*found.Success || entry.Success == nil || !*entry.Success ||
		!jsonEqual(found.Detail, entry.Detail) {
		t.Fatalf("audit log = %#v, want persisted default success and detail %s", found, entry.Detail)
	}

	falseValue := false
	failed := &model.AuditLog{Action: "login", Resource: "user", Success: &falseValue}
	if err := auditLogRepository.Create(context.Background(), failed); err != nil {
		t.Fatalf("Create(failed) error = %v", err)
	}
	var foundFailed model.AuditLog
	if err := database.First(&foundFailed, failed.ID).Error; err != nil {
		t.Fatalf("read failed audit log: %v", err)
	}
	if foundFailed.Success == nil || *foundFailed.Success {
		t.Fatalf("failed audit Success = %v, want false", foundFailed.Success)
	}

	invalid := &model.AuditLog{Action: strings.Repeat("a", 51), Resource: "user"}
	if err := auditLogRepository.Create(context.Background(), invalid); err == nil ||
		!strings.Contains(err.Error(), "create audit log") {
		t.Fatalf("Create(invalid) error = %v, want wrapped create audit log failure", err)
	}
}

// seedAuditLog writes one entry at a chosen time so the window and ordering
// assertions have a deterministic sequence to work with.
func seedAuditLog(
	t *testing.T,
	auditLogs *repository.AuditLogRepository,
	action, resource string,
	userID *int64,
	success bool,
	createdAt time.Time,
) *model.AuditLog {
	t.Helper()
	entry := &model.AuditLog{
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Success:   &success,
		CreatedAt: createdAt,
	}
	if err := auditLogs.Create(context.Background(), entry); err != nil {
		t.Fatalf("seed audit log %q: %v", action, err)
	}
	return entry
}

func TestAuditLogRepositoryListFiltersAndPages(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	auditLogs := repository.NewAuditLog(database)
	actor := createUserWithProfile(t, users, "auditor@njupt.edu.cn")
	base := time.Now().UTC().Truncate(time.Microsecond).Add(-10 * time.Hour)

	seedAuditLog(t, auditLogs, "login", "user", &actor.ID, true, base)
	seedAuditLog(t, auditLogs, "login", "user", nil, false, base.Add(time.Hour))
	seedAuditLog(t, auditLogs, "admin_user_update", "user", &actor.ID, true, base.Add(2*time.Hour))
	seedAuditLog(t, auditLogs, "admin_oauth_client_create", "oauth_client",
		&actor.ID, true, base.Add(3*time.Hour))

	t.Run("unfiltered", func(t *testing.T) {
		entries, total, err := auditLogs.List(context.Background(), repository.AuditLogFilter{Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if total != 4 || len(entries) != 4 {
			t.Fatalf("total/entries = %d/%d, want 4/4", total, len(entries))
		}
	})

	t.Run("newest first", func(t *testing.T) {
		entries, _, err := auditLogs.List(context.Background(), repository.AuditLogFilter{Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		for index := 1; index < len(entries); index++ {
			if entries[index].CreatedAt.After(entries[index-1].CreatedAt) {
				t.Fatalf("entry %d is newer than the one before it; want created_at DESC", index)
			}
		}
	})

	t.Run("by user", func(t *testing.T) {
		entries, total, err := auditLogs.List(context.Background(),
			repository.AuditLogFilter{UserID: &actor.ID, Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if total != 3 || len(entries) != 3 {
			t.Fatalf("total/entries = %d/%d, want 3/3", total, len(entries))
		}
	})

	t.Run("by action and resource", func(t *testing.T) {
		_, total, err := auditLogs.List(context.Background(),
			repository.AuditLogFilter{Action: "login", Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if total != 2 {
			t.Fatalf("login total = %d, want 2", total)
		}
		_, total, err = auditLogs.List(context.Background(),
			repository.AuditLogFilter{Resource: "oauth_client", Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if total != 1 {
			t.Fatalf("oauth_client total = %d, want 1", total)
		}
	})

	t.Run("by outcome", func(t *testing.T) {
		failed := false
		entries, total, err := auditLogs.List(context.Background(),
			repository.AuditLogFilter{Success: &failed, Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if total != 1 || len(entries) != 1 || entries[0].Success == nil || *entries[0].Success {
			t.Fatalf("entries = %+v (total %d), want the single failure", entries, total)
		}
	})

	// The window is inclusive at the start and exclusive at the end, so adjacent
	// windows neither overlap nor skip an entry written exactly on the boundary.
	t.Run("time window boundaries", func(t *testing.T) {
		start := base.Add(time.Hour)
		end := base.Add(3 * time.Hour)
		_, total, err := auditLogs.List(context.Background(),
			repository.AuditLogFilter{StartTime: &start, EndTime: &end, Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if total != 2 {
			t.Fatalf("window total = %d, want 2 (start inclusive, end exclusive)", total)
		}
	})

	t.Run("paging does not overlap", func(t *testing.T) {
		seen := make(map[int64]bool)
		for offset := 0; offset < 4; offset += 2 {
			entries, total, err := auditLogs.List(context.Background(),
				repository.AuditLogFilter{Limit: 2, Offset: offset})
			if err != nil {
				t.Fatalf("List(offset %d): %v", offset, err)
			}
			if total != 4 {
				t.Fatalf("total = %d on offset %d, want 4", total, offset)
			}
			for _, entry := range entries {
				if seen[entry.ID] {
					t.Fatalf("entry %d appeared on two pages", entry.ID)
				}
				seen[entry.ID] = true
			}
		}
		if len(seen) != 4 {
			t.Fatalf("saw %d distinct entries, want 4", len(seen))
		}
	})

	t.Run("a non-positive limit is rejected", func(t *testing.T) {
		if _, _, err := auditLogs.List(context.Background(),
			repository.AuditLogFilter{Limit: 0}); !errors.Is(err, repository.ErrInvalidArgument) {
			t.Fatalf("error = %v, want ErrInvalidArgument", err)
		}
	})
}

// created_at is not unique — one request writes several entries within the same
// clock tick — so id breaks the tie. Without it an offset scan repeats and skips
// rows across pages.
func TestAuditLogRepositoryListIsStableWithinOneTimestamp(t *testing.T) {
	database := setupDatabase(t)
	auditLogs := repository.NewAuditLog(database)
	sameInstant := time.Now().UTC().Truncate(time.Microsecond)
	for index := 0; index < 6; index++ {
		seedAuditLog(t, auditLogs, "login", "user", nil, true, sameInstant)
	}

	seen := make(map[int64]bool)
	for offset := 0; offset < 6; offset += 2 {
		entries, _, err := auditLogs.List(context.Background(),
			repository.AuditLogFilter{Limit: 2, Offset: offset})
		if err != nil {
			t.Fatalf("List(offset %d): %v", offset, err)
		}
		for _, entry := range entries {
			if seen[entry.ID] {
				t.Fatalf("entry %d appeared twice across pages of identical timestamps", entry.ID)
			}
			seen[entry.ID] = true
		}
	}
	if len(seen) != 6 {
		t.Fatalf("saw %d of 6 entries; the page window skipped rows", len(seen))
	}
}

// user_id is ON DELETE SET NULL, so an entry outlives the account it refers to and
// must still be listable.
func TestAuditLogRepositoryListKeepsEntriesWithNullUser(t *testing.T) {
	database := setupDatabase(t)
	auditLogs := repository.NewAuditLog(database)
	seedAuditLog(t, auditLogs, "login", "user", nil, false, time.Now().UTC())

	entries, total, err := auditLogs.List(context.Background(), repository.AuditLogFilter{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 || len(entries) != 1 || entries[0].UserID != nil {
		t.Fatalf("entries = %+v, want one entry with a null user_id", entries)
	}
}
