package repository_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

//nolint:gosec // test data identifiers, not credentials
func TestTokenBlacklistOutboxRepositoryClaimAckFailAndCleanup(t *testing.T) {
	database := setupDatabase(t)
	outbox := repository.NewTokenBlacklistOutbox(database)
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	entries := []model.TokenBlacklistOutbox{
		{TokenID: "outbox-due-1", ExpiresAt: now.Add(time.Hour), NextDeliveryAt: now.Add(-time.Second)},
		{TokenID: "outbox-due-2", ExpiresAt: now.Add(time.Hour), NextDeliveryAt: now},
		{TokenID: "outbox-future", ExpiresAt: now.Add(time.Hour), NextDeliveryAt: now.Add(time.Minute)},
		{TokenID: "outbox-expired", ExpiresAt: now.Add(-time.Second), NextDeliveryAt: now.Add(-time.Second)},
	}
	if err := database.Create(&entries).Error; err != nil {
		t.Fatalf("create token blacklist outbox entries: %v", err)
	}

	claimed, err := outbox.ClaimDue(context.Background(), now, time.Minute, 10)
	if err != nil {
		t.Fatalf("ClaimDue() error = %v", err)
	}
	if len(claimed) != 2 {
		t.Fatalf("ClaimDue() entries = %#v, want two due unexpired entries", claimed)
	}
	for _, entry := range claimed {
		if entry.ClaimToken == nil || *entry.ClaimToken == "" || entry.ClaimedUntil == nil || !entry.ClaimedUntil.Equal(now.Add(time.Minute)) {
			t.Fatalf("claimed entry = %#v, want claim token and lease", entry)
		}
	}
	sort.Slice(claimed, func(left int, right int) bool { return claimed[left].TokenID < claimed[right].TokenID })

	acked, err := outbox.Ack(context.Background(), claimed[0].ID, *claimed[0].ClaimToken)
	if err != nil || !acked {
		t.Fatalf("Ack() = %t, %v, want true, nil", acked, err)
	}
	if wrongAcked, wrongErr := outbox.Ack(context.Background(), claimed[1].ID, "wrong-claim"); wrongErr != nil || wrongAcked {
		t.Fatalf("Ack(wrong claim) = %t, %v, want false, nil", wrongAcked, wrongErr)
	}

	longError := strings.Repeat("x", 2048)
	failed, err := outbox.Fail(context.Background(), claimed[1].ID, *claimed[1].ClaimToken, now, now.Add(5*time.Second), longError)
	if err != nil || !failed {
		t.Fatalf("Fail() = %t, %v, want true, nil", failed, err)
	}
	var failedEntry model.TokenBlacklistOutbox
	if readErr := database.First(&failedEntry, claimed[1].ID).Error; readErr != nil {
		t.Fatalf("read failed entry: %v", readErr)
	}
	if failedEntry.AttemptCount != 1 || failedEntry.ClaimToken != nil || failedEntry.ClaimedUntil != nil ||
		failedEntry.LastAttemptAt == nil || !failedEntry.LastAttemptAt.Equal(now) || failedEntry.LastError == nil || len(*failedEntry.LastError) != 1024 ||
		!failedEntry.NextDeliveryAt.Equal(now.Add(5*time.Second)) {
		t.Fatalf("failed entry = %#v, want released retry state", failedEntry)
	}

	deleted, err := outbox.CleanupExpired(context.Background(), now)
	if err != nil || deleted != 1 {
		t.Fatalf("CleanupExpired() = %d, %v, want 1, nil", deleted, err)
	}
	claimed, err = outbox.ClaimDue(context.Background(), now.Add(5*time.Second), time.Minute, 10)
	if err != nil || len(claimed) != 1 || claimed[0].TokenID != "outbox-due-2" {
		t.Fatalf("ClaimDue(retry) = %#v, %v, want released retry", claimed, err)
	}
}

func TestTokenBlacklistOutboxRepositoryClaimDueIsMultiInstanceSafe(t *testing.T) {
	database := setupDatabase(t)
	outbox := repository.NewTokenBlacklistOutbox(database)
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	entries := make([]model.TokenBlacklistOutbox, 8)
	for index := range entries {
		entries[index] = model.TokenBlacklistOutbox{
			TokenID:        fmt.Sprintf("outbox-concurrent-%02d", index),
			ExpiresAt:      now.Add(time.Hour),
			NextDeliveryAt: now,
		}
	}
	if err := database.Create(&entries).Error; err != nil {
		t.Fatalf("create concurrent outbox entries: %v", err)
	}

	const workers = 4
	results := make(chan []model.TokenBlacklistOutbox, workers)
	errorsByWorker := make(chan error, workers)
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	for range workers {
		go func() {
			defer waitGroup.Done()
			claimed, err := outbox.ClaimDue(context.Background(), now, time.Minute, 2)
			if err != nil {
				errorsByWorker <- err
				return
			}
			results <- claimed
		}()
	}
	waitGroup.Wait()
	close(results)
	close(errorsByWorker)
	for err := range errorsByWorker {
		t.Fatalf("ClaimDue() concurrent error = %v", err)
	}

	claimedIDs := map[int64]struct{}{}
	for claimed := range results {
		for _, entry := range claimed {
			if _, exists := claimedIDs[entry.ID]; exists {
				t.Fatalf("outbox entry %d claimed more than once", entry.ID)
			}
			claimedIDs[entry.ID] = struct{}{}
		}
	}
	if len(claimedIDs) != len(entries) {
		t.Fatalf("unique claimed entries = %d, want %d", len(claimedIDs), len(entries))
	}

	for _, invalid := range []struct {
		name string
		call func() error
	}{
		{"claim", func() error { _, err := outbox.ClaimDue(context.Background(), now, 0, 1); return err }},
		{"ack", func() error { _, err := outbox.Ack(context.Background(), 0, "claim"); return err }},
		{"fail", func() error { _, err := outbox.Fail(context.Background(), 1, "claim", now, now, "error"); return err }},
		{"cleanup", func() error { _, err := outbox.CleanupExpired(context.Background(), time.Time{}); return err }},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			if err := invalid.call(); !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("invalid %s error = %v, want ErrInvalidArgument", invalid.name, err)
			}
		})
	}
}
