package repository_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// A family whose every refresh token is revoked and expired is dead: its origin
// row exists only to date an ID Token's auth_time, and no ID Token will ever be
// minted from a family that cannot rotate. Deleting the whole dead family — the
// origin included — is what keeps oauth_refresh_tokens from growing by one row
// per historical login.
func TestRetentionClearsDeadFamilyRefreshTokens(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	tokens := repository.NewToken(database)
	retention := repository.NewRetention(database)
	user := createUserWithProfile(t, users, "retention-refresh@njupt.edu.cn")
	client := createOAuthClient(t, database)

	// Built through a real rotation rather than two inserts: CreatePair requires a
	// family's first refresh token to be sequence 0 and refuses a second active one,
	// so rotation is the only way to reach the state retention actually meets.
	familyID := "retention-family"
	createTokenPair(t, tokens, "retention-origin", familyID, 0, client.ID, user.ID)
	if _, err := tokens.RotateRefreshToken(
		context.Background(),
		familyID,
		"retention-origin-refresh",
		accessToken("retention-rotated-access", client.ID, user.ID, &familyID),
		refreshToken("retention-rotated-refresh", familyID, 1, client.ID, user.ID),
	); err != nil {
		t.Fatalf("RotateRefreshToken() error = %v", err)
	}

	// Both rows look identical to a naive sweep: revoked long ago and long expired.
	// created_at moves back with expires_at: ck_oauth_refresh_tokens_expiry requires
	// expires_at > created_at, so aging only the expiry is rejected outright.
	dead := time.Now().UTC().Add(-90 * 24 * time.Hour)
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("family_id = ?", familyID).
		Updates(map[string]any{
			"revoked_at": dead,
			"expires_at": dead,
			"created_at": dead.Add(-time.Hour),
		}).Error; err != nil {
		t.Fatalf("age refresh tokens: %v", err)
	}

	removed, err := retention.DeleteRevokedRefreshTokens(context.Background(), time.Now().UTC(), 100)
	if err != nil {
		t.Fatalf("DeleteRevokedRefreshTokens() error = %v", err)
	}
	if removed != 2 {
		t.Fatalf("DeleteRevokedRefreshTokens() removed = %d, want 2 (the whole dead family)", removed)
	}

	var leftover int64
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("family_id = ?", familyID).
		Count(&leftover).Error; err != nil {
		t.Fatalf("count remaining family rows: %v", err)
	}
	if leftover != 0 {
		t.Fatalf("remaining family rows = %d, want 0", leftover)
	}
}

// A family with a live token must survive the sweep: the rotated row is
// unrevoked and unexpired, so it can still rotate, and the origin row it rotates
// from is what dates the next ID Token's auth_time.
func TestRetentionKeepsLiveFamilyRefreshTokens(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	tokens := repository.NewToken(database)
	retention := repository.NewRetention(database)
	user := createUserWithProfile(t, users, "retention-live@njupt.edu.cn")
	client := createOAuthClient(t, database)

	// Rotate so the family has a live sequence-1 token and a revoked origin.
	familyID := "retention-live-family"
	createTokenPair(t, tokens, "retention-live", familyID, 0, client.ID, user.ID)
	if _, err := tokens.RotateRefreshToken(
		context.Background(),
		familyID,
		"retention-live-refresh",
		accessToken("retention-live-rotated-access", client.ID, user.ID, &familyID),
		refreshToken("retention-live-rotated-refresh", familyID, 1, client.ID, user.ID),
	); err != nil {
		t.Fatalf("RotateRefreshToken() error = %v", err)
	}
	// Age only the revoked origin row; the rotated row stays fresh.
	dead := time.Now().UTC().Add(-90 * 24 * time.Hour)
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("token_hash = ?", "retention-live-refresh").
		Updates(map[string]any{
			"revoked_at": dead,
			"expires_at": dead,
			"created_at": dead.Add(-time.Hour),
		}).Error; err != nil {
		t.Fatalf("age origin refresh token: %v", err)
	}

	removed, err := retention.DeleteRevokedRefreshTokens(context.Background(), time.Now().UTC(), 100)
	if err != nil {
		t.Fatalf("DeleteRevokedRefreshTokens() error = %v", err)
	}
	if removed != 0 {
		t.Fatalf("DeleteRevokedRefreshTokens() removed = %d, want 0 for a live family", removed)
	}

	var origin model.OAuthRefreshToken
	if err := database.Where("token_hash = ?", "retention-live-refresh").First(&origin).Error; err != nil {
		t.Fatalf("origin row missing after sweep: %v", err)
	}
}

// The cutoff is the whole safety margin for access-token metadata, since the auth
// middleware reports an unknown JTI as a revocation.
func TestRetentionDeletesOnlyAccessTokensPastCutoff(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	retention := repository.NewRetention(database)
	user := createUserWithProfile(t, users, "retention-access@njupt.edu.cn")
	client := createOAuthClient(t, database)

	now := time.Now().UTC()
	stale := accessToken("retention-stale", client.ID, user.ID, nil)
	stale.ExpiresAt = now.Add(-48 * time.Hour)
	recent := accessToken("retention-recent", client.ID, user.ID, nil)
	recent.ExpiresAt = now.Add(-time.Minute)
	if err := database.Create([]*model.OAuthAccessToken{stale, recent}).Error; err != nil {
		t.Fatalf("create access tokens: %v", err)
	}

	removed, err := retention.DeleteExpiredAccessTokens(context.Background(), now.Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatalf("DeleteExpiredAccessTokens() error = %v", err)
	}
	if removed != 1 {
		t.Fatalf("DeleteExpiredAccessTokens() removed = %d, want 1", removed)
	}
	// The recently expired token's metadata must still be there: its JWT may be
	// inside exp on a client whose clock trails the database.
	var remaining model.OAuthAccessToken
	if err := database.Where("token_id = ?", "retention-recent").First(&remaining).Error; err != nil {
		t.Fatalf("recently expired access token was deleted: %v", err)
	}
}

// Redeemed codes are the common case and the partial V001 index excludes them, so
// V006 adds a full index. Correctness-wise both must go once expired.
func TestRetentionDeletesUsedAndUnusedAuthorizations(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	retention := repository.NewRetention(database)
	user := createUserWithProfile(t, users, "retention-code@njupt.edu.cn")
	client := createOAuthClient(t, database)

	now := time.Now().UTC()
	expired := now.Add(-48 * time.Hour)
	rows := []*model.OAuthAuthorization{
		{
			Code: "retention-code-used", ClientID: client.ID, UserID: user.ID,
			CodeChallenge: "challenge", CodeChallengeMethod: "S256",
			IsUsed: true, CreatedAt: expired.Add(-time.Minute), ExpiresAt: expired,
		},
		{
			Code: "retention-code-unused", ClientID: client.ID, UserID: user.ID,
			CodeChallenge: "challenge", CodeChallengeMethod: "S256",
			CreatedAt: expired.Add(-time.Minute), ExpiresAt: expired,
		},
		{
			Code: "retention-code-live", ClientID: client.ID, UserID: user.ID,
			CodeChallenge: "challenge", CodeChallengeMethod: "S256",
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		},
	}
	if err := database.Create(rows).Error; err != nil {
		t.Fatalf("create authorizations: %v", err)
	}

	removed, err := retention.DeleteExpiredAuthorizations(context.Background(), now.Add(-time.Hour), 100)
	if err != nil {
		t.Fatalf("DeleteExpiredAuthorizations() error = %v", err)
	}
	if removed != 2 {
		t.Fatalf("DeleteExpiredAuthorizations() removed = %d, want 2 (used and unused)", removed)
	}
	var live model.OAuthAuthorization
	if err := database.Where("code = ?", "retention-code-live").First(&live).Error; err != nil {
		t.Fatalf("unexpired authorization was deleted: %v", err)
	}
}

// batchSize bounds one statement so a long-neglected table cannot hold a share of
// the pool that live traffic needs; the caller sweeps again until a pass is short.
func TestRetentionDeleteRespectsBatchSize(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	retention := repository.NewRetention(database)
	user := createUserWithProfile(t, users, "retention-audit@njupt.edu.cn")

	old := time.Now().UTC().Add(-200 * 24 * time.Hour)
	logs := make([]*model.AuditLog, 0, 5)
	for index := range 5 {
		logs = append(logs, &model.AuditLog{
			UserID: &user.ID, Action: "login", Resource: "session",
			Success: boolPtr(true), CreatedAt: old.Add(time.Duration(index) * time.Second),
		})
	}
	if err := database.Create(logs).Error; err != nil {
		t.Fatalf("create audit logs: %v", err)
	}

	cutoff := time.Now().UTC().Add(-90 * 24 * time.Hour)
	removed, err := retention.DeleteExpiredAuditLogs(context.Background(), cutoff, 2)
	if err != nil {
		t.Fatalf("DeleteExpiredAuditLogs() error = %v", err)
	}
	if removed != 2 {
		t.Fatalf("DeleteExpiredAuditLogs() removed = %d, want the batch size 2", removed)
	}
	var count int64
	if err := database.Model(&model.AuditLog{}).Where("created_at < ?", cutoff).Count(&count).Error; err != nil {
		t.Fatalf("count remaining audit logs: %v", err)
	}
	if count != 3 {
		t.Fatalf("remaining aged audit logs = %d, want 3", count)
	}
}

// The advisory lock is what stops two API instances from running the same scan.
// It is session-scoped, so a second holder can only appear after Unlock.
func TestRetentionTryLockIsExclusive(t *testing.T) {
	database := setupDatabase(t)
	first := repository.NewRetention(database)
	ctx := context.Background()

	acquired, err := first.TryLock(ctx)
	if err != nil || !acquired {
		t.Fatalf("TryLock() = %t, %v, want true, nil", acquired, err)
	}

	// A second repository pins its own connection, so it is a distinct session —
	// which is what a second API instance is.
	second := repository.NewRetention(database)
	held, err := second.TryLock(ctx)
	if err != nil {
		t.Fatalf("second TryLock() error = %v", err)
	}
	if held {
		t.Fatal("second TryLock() = true, want false while the lock is held")
	}

	if unlockErr := first.Unlock(ctx); unlockErr != nil {
		t.Fatalf("Unlock() error = %v", unlockErr)
	}
	regained, err := second.TryLock(ctx)
	if err != nil || !regained {
		t.Fatalf("TryLock() after Unlock = %t, %v, want true, nil", regained, err)
	}
	if err := second.Unlock(ctx); err != nil {
		t.Fatalf("second Unlock() error = %v", err)
	}
}

// A family that keeps rotating outlives the origin row's own expires_at, and the
// refresh flow reads that row on every rotation (it dates the family for the
// capability cap). Deleting it while any member of the family is still live would
// make oauth.Service.refresh revoke the whole family and answer 500 — a forced
// logout for an active user. This pins the "live family keeps its origin" half
// of DeleteRevokedRefreshTokens.
func TestRetentionKeepsFamilyOriginReadableAcrossRotations(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	tokens := repository.NewToken(database)
	retention := repository.NewRetention(database)
	user := createUserWithProfile(t, users, "retention-authtime@njupt.edu.cn")
	client := createOAuthClient(t, database)

	familyID := "retention-authtime-family"
	createTokenPair(t, tokens, "retention-authtime", familyID, 0, client.ID, user.ID)

	// Three rotations, sweeping between each, with every dead row well past the
	// cutoff — the state a long-lived session reaches after weeks of refreshing.
	current := "retention-authtime-refresh"
	for sequence := 1; sequence <= 3; sequence++ {
		next := fmt.Sprintf("retention-authtime-refresh-%d", sequence)
		if _, err := tokens.RotateRefreshToken(
			context.Background(),
			familyID,
			current,
			accessToken(fmt.Sprintf("retention-authtime-access-%d", sequence), client.ID, user.ID, &familyID),
			refreshToken(next, familyID, sequence, client.ID, user.ID),
		); err != nil {
			t.Fatalf("RotateRefreshToken(seq %d) error = %v", sequence, err)
		}
		current = next

		dead := time.Now().UTC().Add(-90 * 24 * time.Hour)
		if err := database.Model(&model.OAuthRefreshToken{}).
			Where("family_id = ? AND revoked_at IS NOT NULL", familyID).
			Updates(map[string]any{
				"expires_at": dead,
				"created_at": dead.Add(-time.Hour),
			}).Error; err != nil {
			t.Fatalf("age revoked refresh tokens: %v", err)
		}
		if _, err := retention.DeleteRevokedRefreshTokens(context.Background(), time.Now().UTC(), 100); err != nil {
			t.Fatalf("DeleteRevokedRefreshTokens() error = %v", err)
		}

		// This is the row the refresh flow reads before signing an ID Token; it
		// must survive while the family still holds a live token.
		var origin model.OAuthRefreshToken
		if err := database.Where("family_id = ? AND sequence = 0", familyID).First(&origin).Error; err != nil {
			t.Fatalf("origin row missing after rotation %d = %v, want it intact", sequence, err)
		}
	}
}

func TestRetentionRejectsInvalidArguments(t *testing.T) {
	database := setupDatabase(t)
	retention := repository.NewRetention(database)
	now := time.Now().UTC()

	if _, err := retention.DeleteExpiredAuditLogs(context.Background(), time.Time{}, 10); err == nil {
		t.Error("DeleteExpiredAuditLogs(zero cutoff) error = nil, want ErrInvalidArgument")
	}
	if _, err := retention.DeleteExpiredAuditLogs(context.Background(), now, 0); err == nil {
		t.Error("DeleteExpiredAuditLogs(zero batch) error = nil, want ErrInvalidArgument")
	}
}
