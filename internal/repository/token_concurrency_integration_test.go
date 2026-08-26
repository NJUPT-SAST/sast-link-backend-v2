package repository_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

const tokenFamilyAdvisoryLockNamespace int32 = 0x53415354

func TestTokenRepositoryCreatePairAllowsRotationAfterRefreshRevocation(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotated-family@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotated-family"

	createTokenPair(t, tokenRepository, "rotation-existing", familyID, 0, client.ID, user.ID)
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("family_id = ? AND sequence = ?", familyID, 0).
		Update("revoked_at", time.Now()).Error; err != nil {
		t.Fatalf("revoke rotated refresh token: %v", err)
	}

	access := accessToken("rotation-next-access", client.ID, user.ID, &familyID)
	refresh := refreshToken("rotation-next-refresh", familyID, 1, client.ID, user.ID)
	if err := tokenRepository.CreatePair(context.Background(), access, refresh); err != nil {
		t.Fatalf("CreatePair() after refresh rotation error = %v", err)
	}
	if access.ID == 0 || refresh.ID == 0 {
		t.Fatalf("rotated token-pair IDs = %d/%d, want persisted records", access.ID, refresh.ID)
	}
}

func TestTokenRepositoryCreatePairRejectsRevokedFamily(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "revoked-family@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "revoked-family"

	createTokenPair(t, tokenRepository, "revoked-existing", familyID, 0, client.ID, user.ID)
	if _, err := tokenRepository.RevokeFamily(context.Background(), familyID, time.Now()); err != nil {
		t.Fatalf("RevokeFamily() error = %v", err)
	}

	access := accessToken("revoked-rejected-access", client.ID, user.ID, &familyID)
	refresh := refreshToken("revoked-rejected-refresh", familyID, 1, client.ID, user.ID)
	err := tokenRepository.CreatePair(context.Background(), access, refresh)
	if !errors.Is(err, repository.ErrTokenFamilyRevoked) {
		t.Fatalf("CreatePair() error = %v, want ErrTokenFamilyRevoked", err)
	}

	assertTokenPairAbsent(t, database, access.TokenID, refresh.TokenHash)
}

func TestTokenRepositoryFamilyOperationsWaitForSameAdvisoryLock(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "family-lock@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)

	t.Run("CreatePair", func(t *testing.T) {
		familyID := "locked-create-family"
		access := accessToken("locked-create-access", client.ID, user.ID, &familyID)
		refresh := refreshToken("locked-create-refresh", familyID, 0, client.ID, user.ID)

		assertWaitsForTokenFamilyLock(t, database, familyID, func(ctx context.Context) error {
			return tokenRepository.CreatePair(ctx, access, refresh)
		})
	})

	t.Run("RevokeFamily", func(t *testing.T) {
		familyID := "locked-revoke-family"
		createTokenPair(t, tokenRepository, "locked-revoke", familyID, 0, client.ID, user.ID)

		assertWaitsForTokenFamilyLock(t, database, familyID, func(ctx context.Context) error {
			_, err := tokenRepository.RevokeFamily(ctx, familyID, time.Now())
			return err
		})
	})

	t.Run("RotateRefreshToken", func(t *testing.T) {
		familyID := "locked-rotate-family"
		createTokenPair(t, tokenRepository, "locked-rotate", familyID, 0, client.ID, user.ID)
		access := accessToken("locked-rotate-next-access", client.ID, user.ID, &familyID)
		refresh := refreshToken("locked-rotate-next-refresh", familyID, 1, client.ID, user.ID)

		assertWaitsForTokenFamilyLock(t, database, familyID, func(ctx context.Context) error {
			_, err := tokenRepository.RotateRefreshToken(ctx, familyID, "locked-rotate-refresh", access, refresh)
			return err
		})
	})
}

func TestTokenRepositoryRotateRefreshTokenConcurrentSingleSuccess(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotate-concurrent@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotate-concurrent-family"
	createTokenPair(t, tokenRepository, "rotate-concurrent-current", familyID, 0, client.ID, user.ID)

	const contenders = 8
	start := make(chan struct{})
	results := make(chan error, contenders)
	var waitGroup sync.WaitGroup
	waitGroup.Add(contenders)
	for index := range contenders {
		go func(index int) {
			defer waitGroup.Done()
			<-start
			indexSuffix := fmt.Sprintf("%02d", index)
			access := accessToken("rotate-concurrent-access-"+indexSuffix, client.ID, user.ID, &familyID)
			refresh := refreshToken("rotate-concurrent-refresh-"+indexSuffix, familyID, 1, client.ID, user.ID)
			_, err := tokenRepository.RotateRefreshToken(
				context.Background(),
				familyID,
				"rotate-concurrent-current-refresh",
				access,
				refresh,
			)
			results <- err
		}(index)
	}
	close(start)
	waitGroup.Wait()
	close(results)

	successes := 0
	replays := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, repository.ErrTokenReplay) || errors.Is(err, repository.ErrTokenReplayWithinGrace):
			replays++
		default:
			t.Fatalf("RotateRefreshToken() concurrent error = %v, want nil, ErrTokenReplay, or ErrTokenReplayWithinGrace", err)
		}
	}
	if successes != 1 || replays != contenders-1 {
		t.Fatalf("RotateRefreshToken() concurrent results = %d success, %d replay; want 1/%d", successes, replays, contenders-1)
	}

	var activeRefreshTokens int64
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("family_id = ? AND revoked_at IS NULL", familyID).
		Count(&activeRefreshTokens).Error; err != nil {
		t.Fatalf("count active refresh tokens: %v", err)
	}
	// A concurrent replay is benign (revoked within the grace window): the family
	// must survive so the winning rotation stays live, instead of logging the user
	// out for refreshing on two tabs at once.
	if activeRefreshTokens != 1 {
		t.Fatalf("active refresh tokens after benign concurrent replay = %d, want 1 (the winner's token)", activeRefreshTokens)
	}
}

func TestTokenRepositoryRotateRefreshTokenRejectsTokenExpiredWhileWaitingForFamilyLock(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotate-lock-expired@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotate-lock-expired-family"
	createTokenPair(t, tokenRepository, "rotate-lock-expired-current", familyID, 0, client.ID, user.ID)

	if err := database.Exec(`
		ALTER TABLE oauth_refresh_tokens
		DROP CONSTRAINT ck_oauth_refresh_tokens_expiry
	`).Error; err != nil {
		t.Fatalf("drop refresh expiry constraint: %v", err)
	}
	tokenExpiresAt := time.Now().Add(200 * time.Millisecond)
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("token_hash = ?", "rotate-lock-expired-current-refresh").
		Update("expires_at", tokenExpiresAt).Error; err != nil {
		t.Fatalf("shorten current refresh token expiry: %v", err)
	}

	lockTransaction := database.Begin()
	if lockTransaction.Error != nil {
		t.Fatalf("begin lock transaction: %v", lockTransaction.Error)
	}
	lockReleased := false
	defer func() {
		if !lockReleased {
			_ = lockTransaction.Rollback().Error
		}
	}()
	if err := lockTransaction.Exec(
		"SELECT pg_advisory_xact_lock(?, hashtext(?))",
		tokenFamilyAdvisoryLockNamespace,
		familyID,
	).Error; err != nil {
		t.Fatalf("acquire external token-family lock: %v", err)
	}

	newAccess := accessToken("rotate-lock-expired-new-access", client.ID, user.ID, &familyID)
	newRefresh := refreshToken("rotate-lock-expired-new-refresh", familyID, 1, client.ID, user.ID)
	result := make(chan error, 1)
	go func() {
		_, err := tokenRepository.RotateRefreshToken(
			context.Background(),
			familyID,
			"rotate-lock-expired-current-refresh",
			newAccess,
			newRefresh,
		)
		result <- err
	}()
	// Wait until the rotation is actually blocked on the held lock instead of a
	// fixed sleep, so the release below cannot race the goroutine's arrival.
	blocked := false
	for i := 0; i < 50 && !blocked; i++ {
		var waiters int
		if err := database.Raw(`
			SELECT COUNT(*) FROM pg_stat_activity
			WHERE wait_event_type = 'Lock' AND state = 'active'
		`).Scan(&waiters).Error; err != nil {
			t.Fatalf("count lock waiters: %v", err)
		}
		blocked = waiters > 0
		if !blocked {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !blocked {
		t.Fatal("RotateRefreshToken never blocked on the token-family lock")
	}
	// The rotation stays blocked on the lock while the token crosses its expiry,
	// so the release below hands it an already-expired token — the ErrTokenExpired
	// this test asserts. Polling the clock keeps it load-independent.
	for time.Now().Before(tokenExpiresAt.Add(20 * time.Millisecond)) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := lockTransaction.Rollback().Error; err != nil {
		t.Fatalf("release external token-family lock: %v", err)
	}
	lockReleased = true

	select {
	case err := <-result:
		if !errors.Is(err, repository.ErrTokenExpired) {
			t.Fatalf("RotateRefreshToken(expired while waiting) error = %v, want ErrTokenExpired", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RotateRefreshToken remained blocked after lock release")
	}
	assertTokenPairAbsent(t, database, newAccess.TokenID, newRefresh.TokenHash)
}

func assertWaitsForTokenFamilyLock(
	t *testing.T,
	database *gorm.DB,
	familyID string,
	operation func(context.Context) error,
) {
	t.Helper()

	lockTransaction := database.Begin()
	if lockTransaction.Error != nil {
		t.Fatalf("begin lock transaction: %v", lockTransaction.Error)
	}
	lockReleased := false
	defer func() {
		if !lockReleased {
			_ = lockTransaction.Rollback().Error
		}
	}()

	if err := lockTransaction.Exec(
		"SELECT pg_advisory_xact_lock(?, hashtext(?))",
		tokenFamilyAdvisoryLockNamespace,
		familyID,
	).Error; err != nil {
		t.Fatalf("acquire external token-family lock: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		result <- operation(ctx)
	}()
	<-started

	select {
	case err := <-result:
		t.Fatalf("operation completed while family lock was held: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	if err := lockTransaction.Rollback().Error; err != nil {
		t.Fatalf("release external token-family lock: %v", err)
	}
	lockReleased = true

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("operation after family lock release: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("operation remained blocked after family lock release: %v", ctx.Err())
	}
}

func assertTokenPairAbsent(t *testing.T, database *gorm.DB, tokenID string, tokenHash string) {
	t.Helper()

	var accessCount int64
	if err := database.Model(&model.OAuthAccessToken{}).
		Where("token_id = ?", tokenID).
		Count(&accessCount).Error; err != nil {
		t.Fatalf("count rejected access token: %v", err)
	}
	var refreshCount int64
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("token_hash = ?", tokenHash).
		Count(&refreshCount).Error; err != nil {
		t.Fatalf("count rejected refresh token: %v", err)
	}
	if accessCount != 0 || refreshCount != 0 {
		t.Fatalf("rejected token-pair counts = %d access, %d refresh; want 0 each", accessCount, refreshCount)
	}
}

// TestTokenRepositoryBulkRevokeWaitsForFamilyLockAndRevokesRotatedToken
// reproduces the rotation-vs-bulk-revoke race that previously let a refresh
// token escape a password change: a rotation commits its rotated row while the
// bulk revocation is already in flight, and the revocation's UPDATE statement
// snapshot never sees the row. The revocation must take the family advisory
// lock first, which serializes it after the rotation; the rotated row must then
// be revoked like every other.
func TestTokenRepositoryBulkRevokeWaitsForFamilyLockAndRevokesRotatedToken(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "bulk-revoke-rotate-race@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "bulk-revoke-rotate-race-family"
	createTokenPair(t, tokenRepository, "bulk-revoke-rotate-race-current", familyID, 0, client.ID, user.ID)

	// Simulate a rotation that is past its lock acquisition and about to insert
	// the rotated row: hold the family advisory lock and the current refresh
	// token's row lock in a separate transaction.
	lockTransaction := database.Begin()
	if lockTransaction.Error != nil {
		t.Fatalf("begin rotation transaction: %v", lockTransaction.Error)
	}
	rotationCommitted := false
	defer func() {
		if !rotationCommitted {
			_ = lockTransaction.Rollback().Error
		}
	}()
	if err := lockTransaction.Exec(
		"SELECT pg_advisory_xact_lock(?, hashtext(?))",
		tokenFamilyAdvisoryLockNamespace,
		familyID,
	).Error; err != nil {
		t.Fatalf("acquire external token-family lock: %v", err)
	}
	var current model.OAuthRefreshToken
	if err := lockTransaction.
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("token_hash = ?", "bulk-revoke-rotate-race-current-refresh").
		First(&current).Error; err != nil {
		t.Fatalf("lock current refresh token row: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	revoked := make(chan error, 1)
	go func() {
		_, err := tokenRepository.RevokeAllByUser(ctx, user.ID, time.Now())
		revoked <- err
	}()

	// The revocation must be parked on a lock (the family advisory lock with the
	// fix, the current row's lock without it): poll pg_stat_activity until the
	// revoke session is provably waiting, so the rotation below provably commits
	// after the revocation's UPDATE statement began. Without that proof the test
	// could pass pre-fix by letting the revocation start only after the rotation
	// committed — the very race the fix exists to close.
	blockedDeadline := time.Now().Add(10 * time.Second)
	blocked := false
	for time.Now().Before(blockedDeadline) {
		select {
		case err := <-revoked:
			t.Fatalf("RevokeAllByUser completed while the family lock was held (error = %v); lockLiveTokenFamilies is not serializing", err)
		default:
		}
		var waiters int
		if err := database.Raw(`
			SELECT COUNT(*) FROM pg_stat_activity
			WHERE wait_event_type = 'Lock' AND state = 'active'
		`).Scan(&waiters).Error; err != nil {
			t.Fatalf("count lock waiters: %v", err)
		}
		if waiters > 0 {
			blocked = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("RevokeAllByUser never blocked on a lock")
	}

	// The rotation finishes: revoke the current row and insert the rotated row,
	// exactly like rotateRefreshToken would after its lock acquisition.
	if err := lockTransaction.Model(&model.OAuthRefreshToken{}).
		Where("id = ?", current.ID).
		Update("revoked_at", time.Now()).Error; err != nil {
		t.Fatalf("revoke current refresh token in rotation transaction: %v", err)
	}
	rotated := refreshToken("bulk-revoke-rotate-race-rotated-refresh", familyID, 1, client.ID, user.ID)
	if err := lockTransaction.Create(rotated).Error; err != nil {
		t.Fatalf("insert rotated refresh token: %v", err)
	}
	if err := lockTransaction.Commit().Error; err != nil {
		t.Fatalf("commit rotation transaction: %v", err)
	}
	rotationCommitted = true

	select {
	case err := <-revoked:
		if err != nil {
			t.Fatalf("RevokeAllByUser after lock release: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("RevokeAllByUser remained blocked after lock release: %v", ctx.Err())
	}

	// The rotated row was inserted by a rotation that committed before the
	// revocation's read set was established; the revocation must have cut it.
	// Pre-fix, this row escaped the UPDATE's snapshot and stayed live.
	var rotatedRevoked model.OAuthRefreshToken
	if err := database.Where("token_hash = ?", "bulk-revoke-rotate-race-rotated-refresh").
		First(&rotatedRevoked).Error; err != nil {
		t.Fatalf("read rotated refresh token: %v", err)
	}
	if rotatedRevoked.RevokedAt == nil {
		t.Fatal("rotated refresh token escaped the bulk revocation: revoked_at IS NULL")
	}
}
