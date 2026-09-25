package repository_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// Consume and signing occur before persistence. Revocation in that gap must
// fence the exact old code, including after the same client is consented again.
func TestConsumedCodeCannotOutliveGrantRevocation(t *testing.T) {
	db := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(db), "grant-fence@njupt.edu.cn")
	client := createOAuthClient(t, db)
	authz, tokens := repository.NewOAuthAuthorization(db), repository.NewToken(db)
	for _, action := range []string{"revoke", "reconsent", "replay"} {
		t.Run(action, func(t *testing.T) {
			code := testAuthorization("fence-"+action, client.ID, user.ID, time.Now().Add(time.Hour))
			if err := authz.CreateWithGrant(context.Background(), code); err != nil {
				t.Fatal(err)
			}
			_, version, consumeErr := authz.Consume(context.Background(), code.Code, time.Now(), client.ID)
			if consumeErr != nil {
				t.Fatal(consumeErr)
			}
			if action == "replay" {
				if _, _, err := authz.Consume(context.Background(), code.Code, time.Now(), client.ID); !errors.Is(err, repository.ErrAuthorizationReplayed) {
					t.Fatalf("replay: %v", err)
				}
			} else {
				if _, err := tokens.RevokeUserClientTokens(context.Background(), user.ID, client.ID, time.Now()); err != nil {
					t.Fatal(err)
				}
				if action == "reconsent" {
					next := testAuthorization("fresh-consent", client.ID, user.ID, time.Now().Add(time.Hour))
					if err := authz.CreateWithGrant(context.Background(), next); err != nil {
						t.Fatal(err)
					}
				}
			}
			access := accessToken("fenced-"+action, client.ID, user.ID, code.FamilyID)
			refresh := refreshToken("fenced-"+action, *code.FamilyID, 0, client.ID, user.ID)
			err := tokens.CreatePairWithUserAndClientLock(context.Background(), user.ID, client.ID, version, code.ID, access, refresh, nil)
			if !errors.Is(err, repository.ErrNotFound) {
				t.Fatalf("late pair error=%v, want ErrNotFound", err)
			}
			assertTokenPairAbsent(t, db, access.TokenID, refresh.TokenHash)
		})
	}
}

// Block the real pair writer at its family lock after it locks the code. The
// real revoke must wait for the pair, then revoke it and publish its outbox row.
func TestGrantRevokeWaitsForRedemptionAndRevokesItsPair(t *testing.T) {
	db := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(db), "grant-wait@njupt.edu.cn")
	client := createOAuthClient(t, db)
	authz, tokens := repository.NewOAuthAuthorization(db), repository.NewToken(db)
	code := testAuthorization("grant-wait", client.ID, user.ID, time.Now().Add(time.Hour))
	if err := authz.CreateWithGrant(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	_, version, consumeErr := authz.Consume(context.Background(), code.Code, time.Now(), client.ID)
	if consumeErr != nil {
		t.Fatal(consumeErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	blocker := db.WithContext(ctx).Begin()
	defer blocker.Rollback()
	// Use the same hash namespace as the production family lock.
	if err := blocker.Exec("SELECT pg_advisory_xact_lock(?, hashtext(?))", int32(0x53415354), *code.FamilyID).Error; err != nil {
		t.Fatal(err)
	}
	access := accessToken("grant-wait-access", client.ID, user.ID, code.FamilyID)
	refresh := refreshToken("grant-wait-refresh", *code.FamilyID, 0, client.ID, user.ID)
	created := make(chan error, 1)
	go func() {
		created <- tokens.CreatePairWithUserAndClientLock(ctx, user.ID, client.ID, version, code.ID, access, refresh, nil)
	}()
	waitForSQLLock(t, ctx, db, "%pg_advisory_xact_lock%")
	revoked := make(chan error, 1)
	go func() { _, err := tokens.RevokeUserClientTokens(ctx, user.ID, client.ID, time.Now()); revoked <- err }()
	waitForSQLLock(t, ctx, db, "%DELETE FROM \"oauth_authorizations\"%")
	if err := blocker.Commit().Error; err != nil {
		t.Fatal(err)
	}
	if err := <-created; err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	got, findErr := tokens.FindRefreshToken(ctx, refresh.TokenHash)
	if findErr != nil || got.RevokedAt == nil {
		t.Fatalf("refresh=%+v err=%v, want revoked", got, findErr)
	}
	var count int64
	if err := db.Model(&model.OAuthAccessToken{}).Where("token_id = ? AND revoked_at IS NULL", access.TokenID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("access survived revoke")
	}
	if err := db.Model(&model.TokenBlacklistOutbox{}).Where("token_id = ?", access.TokenID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("outbox rows=%d, want 1", count)
	}

}

func waitForSQLLock(t *testing.T, ctx context.Context, db *gorm.DB, query string) {
	t.Helper()
	for {
		var count int64
		if err := db.WithContext(ctx).Raw("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE ?", query).Scan(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// A concurrent successful redemption shares the client/user read locks. This
// catches accidental FOR UPDATE on a popular client's row without timing a
// throughput threshold: the second transaction must finish while SHARE is held.
func TestRedemptionDoesNotSerializeOnClientReaders(t *testing.T) {
	db := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(db), "shared-read@njupt.edu.cn")
	client := createOAuthClient(t, db)
	authz, tokens := repository.NewOAuthAuthorization(db), repository.NewToken(db)
	code := testAuthorization("shared-read", client.ID, user.ID, time.Now().Add(time.Hour))
	if err := authz.CreateWithGrant(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	_, version, consumeErr := authz.Consume(context.Background(), code.Code, time.Now(), client.ID)
	if consumeErr != nil {
		t.Fatal(consumeErr)
	}
	held := db.Begin()
	defer held.Rollback()
	if err := held.Exec(`SELECT id FROM "user" WHERE id = ? FOR SHARE`, user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := held.Exec("SELECT id FROM oauth_clients WHERE id = ? FOR SHARE", client.ID).Error; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	access := accessToken("shared-access", client.ID, user.ID, code.FamilyID)
	refresh := refreshToken("shared-refresh", *code.FamilyID, 0, client.ID, user.ID)
	if err := tokens.CreatePairWithUserAndClientLock(ctx, user.ID, client.ID, version, code.ID, access, refresh, nil); err != nil {
		t.Fatal(fmt.Errorf("independent reader blocked redemption: %w", err))
	}
}

func TestGrantRevocationRollsBackAsOneUnit(t *testing.T) {
	db := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(db), "grant-rollback@njupt.edu.cn")
	client := createOAuthClient(t, db)
	authz, tokens := repository.NewOAuthAuthorization(db), repository.NewToken(db)
	code := testAuthorization("grant-rollback", client.ID, user.ID, time.Now().Add(time.Hour))
	if err := authz.CreateWithGrant(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	access := accessToken("rollback-access", client.ID, user.ID, code.FamilyID)
	refresh := refreshToken("rollback-refresh", *code.FamilyID, 0, client.ID, user.ID)
	if err := tokens.CreatePair(context.Background(), access, refresh); err != nil {
		t.Fatal(err)
	}
	// Fail after grant/code deletion and the access-token UPDATE. None of them
	// may commit if the refresh-token change cannot complete.
	if err := db.Exec("ALTER TABLE oauth_refresh_tokens ADD CONSTRAINT test_revoke_failure CHECK (revoked_at IS NULL) NOT VALID").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.RevokeUserClientTokens(context.Background(), user.ID, client.ID, time.Now()); err == nil {
		t.Fatal("expected injected constraint failure")
	}
	for _, table := range []string{"oauth_grants", "oauth_authorizations"} {
		var count int64
		if err := db.Table(table).Where("user_id = ? AND client_id = ?", user.ID, client.ID).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s count=%d after rollback", table, count)
		}
	}
	got, err := tokens.FindAccessTokenByJTI(context.Background(), access.TokenID)
	if err != nil || got.RevokedAt != nil {
		t.Fatalf("access=%+v err=%v after rollback", got, err)
	}
}

func TestRedemptionRechecksExpiryAfterWaitingForCodeLock(t *testing.T) {
	db := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(db), "expiry-wait@njupt.edu.cn")
	client := createOAuthClient(t, db)
	authz, tokens := repository.NewOAuthAuthorization(db), repository.NewToken(db)
	code := testAuthorization("expiry-wait", client.ID, user.ID, time.Now().Add(time.Hour))
	if err := authz.CreateWithGrant(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	_, version, consumeErr := authz.Consume(context.Background(), code.Code, time.Now(), client.ID)
	if consumeErr != nil {
		t.Fatal(consumeErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	held := db.WithContext(ctx).Begin()
	defer held.Rollback()
	if err := held.Exec("SELECT id FROM oauth_authorizations WHERE id = ? FOR UPDATE", code.ID).Error; err != nil {
		t.Fatal(err)
	}
	access := accessToken("expiry-wait-access", client.ID, user.ID, code.FamilyID)
	refresh := refreshToken("expiry-wait-refresh", *code.FamilyID, 0, client.ID, user.ID)
	done := make(chan error, 1)
	go func() {
		done <- tokens.CreatePairWithUserAndClientLock(ctx, user.ID, client.ID, version, code.ID, access, refresh, nil)
	}()
	waitForSQLLock(t, ctx, db, "%FROM \"oauth_authorizations\"%FOR SHARE%")
	if err := held.Model(code).Update("expires_at", time.Now()).Error; err != nil {
		t.Fatal(err)
	}
	if err := held.Commit().Error; err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expired during wait: %v", err)
	}
	assertTokenPairAbsent(t, db, access.TokenID, refresh.TokenHash)
}

// All bulk revocation callers must acquire code rows before family locks. If
// this waits on a code while holding its family, grant revoke can deadlock it.
func TestBulkUserRevocationLocksCodesBeforeFamilies(t *testing.T) {
	db := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(db), "bulk-order@njupt.edu.cn")
	client := createOAuthClient(t, db)
	authz, tokens := repository.NewOAuthAuthorization(db), repository.NewToken(db)
	code := testAuthorization("bulk-order", client.ID, user.ID, time.Now().Add(time.Hour))
	if err := authz.CreateWithGrant(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	access := accessToken("bulk-order-access", client.ID, user.ID, code.FamilyID)
	refresh := refreshToken("bulk-order-refresh", *code.FamilyID, 0, client.ID, user.ID)
	if err := tokens.CreatePair(context.Background(), access, refresh); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	held := db.WithContext(ctx).Begin()
	defer held.Rollback()
	if err := held.Exec("SELECT id FROM oauth_authorizations WHERE id = ? FOR UPDATE", code.ID).Error; err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := tokens.RevokeAllByUser(ctx, user.ID, time.Now()); done <- err }()
	waitForSQLLock(t, ctx, db, "%UPDATE \"oauth_authorizations\"%")
	var available bool
	if err := held.Raw("SELECT pg_try_advisory_xact_lock(?, hashtext(?))", int32(0x53415354), *code.FamilyID).Scan(&available).Error; err != nil {
		t.Fatal(err)
	}
	if !available {
		t.Fatal("bulk revoke holds family while waiting for code: inverted lock order")
	}
	if err := held.Commit().Error; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestClientDeletionLocksCodesBeforeFamilies(t *testing.T) {
	db := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(db), "client-delete-order@njupt.edu.cn")
	client := createOAuthClient(t, db)
	authz, tokens := repository.NewOAuthAuthorization(db), repository.NewToken(db)
	code := testAuthorization("client-delete-order", client.ID, user.ID, time.Now().Add(time.Hour))
	if err := authz.CreateWithGrant(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	access := accessToken("client-delete-order-access", client.ID, user.ID, code.FamilyID)
	refresh := refreshToken("client-delete-order-refresh", *code.FamilyID, 0, client.ID, user.ID)
	if err := tokens.CreatePair(context.Background(), access, refresh); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	held := db.WithContext(ctx).Begin()
	defer held.Rollback()
	if err := held.Exec("SELECT id FROM oauth_authorizations WHERE id = ? FOR UPDATE", code.ID).Error; err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := repository.NewOAuthClient(db).DeleteAndRevoke(ctx, client.ID, time.Now())
		done <- err
	}()
	waitForSQLLock(t, ctx, db, "%DELETE FROM \"oauth_authorizations\"%")
	var available bool
	if err := held.Raw("SELECT pg_try_advisory_xact_lock(?, hashtext(?))", int32(0x53415354), *code.FamilyID).Scan(&available).Error; err != nil {
		t.Fatal(err)
	}
	if !available {
		t.Fatal("client delete holds family while waiting for code")
	}
	if err := held.Commit().Error; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConsumeRejectsForeignClientBeforeAnyMutation(t *testing.T) {
	db := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(db), "consume-client@njupt.edu.cn")
	client := createOAuthClient(t, db)
	authz := repository.NewOAuthAuthorization(db)
	code := testAuthorization("consume-client", client.ID, user.ID, time.Now().Add(time.Hour).Truncate(time.Microsecond))
	if err := authz.CreateWithGrant(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	for _, used := range []bool{false, true} {
		if err := db.Model(code).Update("is_used", used).Error; err != nil {
			t.Fatal(err)
		}
		if _, _, err := authz.Consume(context.Background(), code.Code, time.Now(), client.ID+999); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("foreign consume: %v", err)
		}
		var stored model.OAuthAuthorization
		if err := db.First(&stored, code.ID).Error; err != nil {
			t.Fatal(err)
		}
		if stored.IsUsed != used || !stored.ExpiresAt.Equal(code.ExpiresAt) {
			t.Fatal("foreign client changed victim code")
		}
	}
}
