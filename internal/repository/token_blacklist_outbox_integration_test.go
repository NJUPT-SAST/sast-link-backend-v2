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
	"unicode/utf8"

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

// Truncation must land on a rune boundary. The failure text comes from a provider
// or a driver and routinely carries non-ASCII; a byte-index cut that splits a
// multi-byte sequence produces invalid UTF-8, which PostgreSQL rejects with
// "invalid byte sequence for encoding" — so recording the failure would itself
// fail, and the row would sit in its lease until that lease expired. A transient
// network error would then turn into a delayed retry for no reason anyone could
// see in the logs.
func TestTokenBlacklistOutboxRepositoryFailTruncatesOnARuneBoundary(t *testing.T) {
	database := setupDatabase(t)
	outbox := repository.NewTokenBlacklistOutbox(database)
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	entry := model.TokenBlacklistOutbox{ //nolint:gosec // Non-secret fixture row id, not a credential.
		TokenID:        "outbox-utf8",
		ExpiresAt:      now.Add(time.Hour),
		NextDeliveryAt: now.Add(-time.Second),
	}
	if err := database.Create(&entry).Error; err != nil {
		t.Fatalf("create outbox entry: %v", err)
	}
	claimed, err := outbox.ClaimDue(context.Background(), now, time.Minute, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimDue() = %#v, %v, want one entry", claimed, err)
	}

	// Three bytes per rune over a length that is not a multiple of three, so a cut
	// at byte 1024 lands inside a character.
	deliveryError := strings.Repeat("错", 700)
	failed, err := outbox.Fail(context.Background(), claimed[0].ID, *claimed[0].ClaimToken, now,
		now.Add(5*time.Second), deliveryError)
	if err != nil || !failed {
		t.Fatalf("Fail() = %t, %v, want true, nil: a byte-index cut is rejected by PostgreSQL here", failed, err)
	}

	var stored model.TokenBlacklistOutbox
	if readErr := database.First(&stored, claimed[0].ID).Error; readErr != nil {
		t.Fatalf("read failed entry: %v", readErr)
	}
	if stored.LastError == nil {
		t.Fatal("last_error was not recorded")
	}
	if !utf8.ValidString(*stored.LastError) {
		t.Fatalf("last_error holds invalid UTF-8 (%d bytes)", len(*stored.LastError))
	}
	if len(*stored.LastError) > 1024 {
		t.Fatalf("last_error length = %d bytes, want at most 1024", len(*stored.LastError))
	}
	// The cap is a ceiling, not a target: a generous cut would satisfy the byte
	// bound while discarding text that fits.
	if len(*stored.LastError) < 1021 {
		t.Fatalf("last_error length = %d bytes, want the full 1024-byte budget used (1021-1024)", len(*stored.LastError))
	}
}
