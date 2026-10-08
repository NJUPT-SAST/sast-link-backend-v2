package repository_test

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	internalredis "github.com/NJUPT-SAST/sast-link-backend-v2/internal/redis"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/shared"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
)

type loseCommittedReply struct {
	internalredis.Cmdable
	lost   bool
	replay func() *goredis.Cmd
}

func (d *loseCommittedReply) Eval(ctx context.Context, script string, keys []string, args ...any) *goredis.Cmd {
	result := d.Cmdable.Eval(ctx, script, keys, args...)
	if !d.lost && result.Err() == nil {
		d.lost = true
		d.replay = func() *goredis.Cmd { return d.Cmdable.Eval(ctx, script, keys, args...) }
		return goredis.NewCmdResult(nil, io.EOF)
	}
	return result
}
func (d *loseCommittedReply) EvalSha(ctx context.Context, sha string, keys []string, args ...any) *goredis.Cmd {
	result := d.Cmdable.EvalSha(ctx, sha, keys, args...)
	if !d.lost && result.Err() == nil {
		d.lost = true
		d.replay = func() *goredis.Cmd { return d.Cmdable.EvalSha(ctx, sha, keys, args...) }
		return goredis.NewCmdResult(nil, io.EOF)
	}
	return result
}

func TestRegressionEvictionJournalSurvivesLostReply(t *testing.T) {
	db := setupDatabase(t)
	tokens := repository.NewToken(db)
	users := repository.NewUser(db)
	user := createUserWithProfile(t, users, "journal@sast.fun")
	client := createOAuthClient(t, db)
	createTokenPair(t, tokens, "old", "old-family", 0, client.ID, user.ID)
	createTokenPair(t, tokens, "new", "new-family", 0, client.ID, user.ID)
	redisClient := testutil.StartRedis(t)
	store := internalredis.Store{Client: redisClient, Keys: internalredis.NewKeys("journal")}
	ctx := context.Background()
	now := time.Now()
	if _, err := store.RegisterDevice(ctx, user.ID, "old-family", "ua", "ip", now, time.Hour, 1); err != nil {
		t.Fatal(err)
	}
	lost := &loseCommittedReply{Cmdable: redisClient}
	store.Client = lost
	_, err := store.RegisterDevice(ctx, user.ID, "new-family", "ua", "ip", now.Add(time.Second), time.Hour, 1, shared.DeviceOperation{TokenHash: "new-refresh", ExpiresAt: now.Add(time.Hour)})
	if err == nil || !lost.lost {
		t.Fatalf("expected lost actual Lua reply: %v", err)
	}
	if replayed, replayErr := lost.replay().Text(); replayErr != nil || replayed != "old-family" {
		t.Fatalf("idempotent replay=%q %v", replayed, replayErr)
	}
	store.Client = redisClient
	pending, err := store.PendingDeviceEvictions(ctx, 0, 100)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending=%v error=%v", pending, err)
	}
	item := pending[0]
	for range 2 { // replay after a failed ack is harmless
		resolved, resolveErr := tokens.ResolveDeviceEviction(ctx, item.UserID, item.TokenHash, item.SourceFamily, item.Evicted, time.Unix(item.ExpiresAt, 0), now)
		if resolveErr != nil || !resolved {
			t.Fatalf("resolve=%v error=%v", resolved, resolveErr)
		}
	}
	old, err := tokens.FindRefreshToken(ctx, "old-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if old.RevokedAt == nil {
		t.Fatal("evicted family remains live")
	}
	if ackErr := store.AckDeviceEviction(ctx, item.Receipt); ackErr != nil {
		t.Fatal(ackErr)
	}
	pending, err = store.PendingDeviceEvictions(ctx, 0, 100)
	if err != nil || len(pending) != 0 {
		t.Fatalf("acked pending=%v %v", pending, err)
	}
}

func TestRegressionUncommittedAndForeignEvictionNeverRevokes(t *testing.T) {
	db := setupDatabase(t)
	tokens := repository.NewToken(db)
	users := repository.NewUser(db)
	user := createUserWithProfile(t, users, "source@sast.fun")
	foreign := createUserWithProfile(t, users, "foreign@sast.fun")
	client := createOAuthClient(t, db)
	createTokenPair(t, tokens, "source", "source-family", 0, client.ID, user.ID)
	createTokenPair(t, tokens, "target", "target-family", 0, client.ID, user.ID)
	createTokenPair(t, tokens, "foreign", "foreign-family", 0, client.ID, foreign.ID)
	ctx := context.Background()
	now := time.Now()
	resolved, err := tokens.ResolveDeviceEviction(ctx, user.ID, "uncommitted", "source-family", "target-family", now.Add(time.Hour), now)
	if err != nil || resolved {
		t.Fatalf("uncommitted resolved=%v error=%v", resolved, err)
	}
	resolved, err = tokens.ResolveDeviceEviction(ctx, user.ID, "uncommitted", "source-family", "target-family", now.Add(-time.Second), now)
	if err != nil || !resolved {
		t.Fatalf("expired missing proof resolved=%v error=%v", resolved, err)
	}
	if _, err := tokens.ResolveDeviceEviction(ctx, user.ID, "source-refresh", "source-family", "foreign-family", now.Add(time.Hour), now); err == nil {
		t.Fatal("foreign family accepted")
	}
	for _, hash := range []string{"target-refresh", "foreign-refresh"} {
		token, err := tokens.FindRefreshToken(ctx, hash)
		if err != nil {
			t.Fatal(err)
		}
		if token.RevokedAt != nil {
			t.Fatalf("%s wrongly revoked", hash)
		}
	}
}

func TestRegressionEvictionWaitsForExactRefreshCommit(t *testing.T) {
	db := setupDatabase(t)
	tokens := repository.NewToken(db)
	users := repository.NewUser(db)
	user := createUserWithProfile(t, users, "late-proof@sast.fun")
	client := createOAuthClient(t, db)
	createTokenPair(t, tokens, "source", "source-family", 0, client.ID, user.ID)
	createTokenPair(t, tokens, "target", "target-family", 0, client.ID, user.ID)
	ctx := context.Background()
	now := time.Now()
	resolved, err := tokens.ResolveDeviceEviction(ctx, user.ID, "late-refresh", "source-family", "target-family", now.Add(time.Hour), now)
	if err != nil || resolved {
		t.Fatalf("pending resolve=%v %v", resolved, err)
	}
	family := "source-family"
	if _, err = tokens.RotateRefreshToken(ctx, family, "source-refresh", accessToken("late-access", client.ID, user.ID, &family), refreshToken("late-refresh", family, 1, client.ID, user.ID)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, e := tokens.ResolveDeviceEviction(ctx, user.ID, "late-refresh", family, "target-family", now.Add(time.Hour), now)
			if e != nil || !ok {
				t.Errorf("concurrent resolve=%v %v", ok, e)
			}
		}()
	}
	wg.Wait()
	token, err := tokens.FindRefreshToken(ctx, "target-refresh")
	if err != nil || token.RevokedAt == nil {
		t.Fatalf("target=%v %v", token, err)
	}
}

func TestDeviceEvictionProofSurvivesRefreshFamilyRetention(t *testing.T) {
	db := setupDatabase(t)
	tokens := repository.NewToken(db)
	users := repository.NewUser(db)
	retention := repository.NewRetention(db)
	user := createUserWithProfile(t, users, "proof-retention@sast.fun")
	client := createOAuthClient(t, db)
	createTokenPair(t, tokens, "source", "source-family", 0, client.ID, user.ID)
	createTokenPair(t, tokens, "target", "target-family", 0, client.ID, user.ID)
	ctx := context.Background()
	now := time.Now()
	family := "source-family"
	if _, err := tokens.RotateRefreshToken(ctx, family, "source-refresh", accessToken("latest-access", client.ID, user.ID, &family), refreshToken("latest-refresh", family, 1, client.ID, user.ID)); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-72 * time.Hour)
	if err := db.Model(&model.OAuthRefreshToken{}).Where("token_hash = ?", "source-refresh").Updates(map[string]any{"created_at": old.Add(-time.Hour), "expires_at": old, "revoked_at": old}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.OAuthAccessToken{}).Where("token_id = ?", "source-access").Updates(map[string]any{"created_at": old.Add(-time.Hour), "expires_at": old}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := retention.DeleteExpiredAccessTokens(ctx, now.Add(-24*time.Hour), 100); err != nil {
		t.Fatal(err)
	}
	if _, err := retention.DeleteRevokedRefreshTokens(ctx, now.Add(-24*time.Hour), 100); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.FindRefreshToken(ctx, "source-refresh"); err != nil {
		t.Fatalf("active-family proof lost: %v", err)
	}
	resolved, err := tokens.ResolveDeviceEviction(ctx, user.ID, "source-refresh", family, "target-family", old, now)
	if err != nil || !resolved {
		t.Fatalf("delayed journal resolve=%v error=%v", resolved, err)
	}
	target, err := tokens.FindRefreshToken(ctx, "target-refresh")
	if err != nil || target.RevokedAt == nil {
		t.Fatalf("target=%v error=%v", target, err)
	}
}
