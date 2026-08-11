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

func TestTokenRepositoryCreatePairAndFindRefreshToken(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "tokens@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "token-pair-family"
	access := accessToken("token-pair-access", client.ID, user.ID, &familyID)
	refresh := refreshToken("token-pair-refresh", familyID, 0, client.ID, user.ID)

	if err := tokenRepository.CreatePair(context.Background(), access, refresh); err != nil {
		t.Fatalf("CreatePair() error = %v", err)
	}
	if access.ID == 0 || refresh.ID == 0 {
		t.Fatalf("CreatePair() IDs = %d, %d; want persisted records", access.ID, refresh.ID)
	}
	found, err := tokenRepository.FindRefreshToken(context.Background(), refresh.TokenHash)
	if err != nil {
		t.Fatalf("FindRefreshToken() error = %v", err)
	}
	if found.ID != refresh.ID || found.TokenHash != refresh.TokenHash {
		t.Fatalf("FindRefreshToken() = %#v, want %#v", found, refresh)
	}
	foundAccess, err := tokenRepository.FindAccessTokenByJTI(context.Background(), access.TokenID)
	if err != nil {
		t.Fatalf("FindAccessTokenByJTI() error = %v", err)
	}
	if foundAccess.ID != access.ID || foundAccess.TokenID != access.TokenID {
		t.Fatalf("FindAccessTokenByJTI() = %#v, want %#v", foundAccess, access)
	}
	_, err = tokenRepository.FindAccessTokenByJTI(context.Background(), "absent-access-jti")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindAccessTokenByJTI(absent) error = %v, want ErrNotFound", err)
	}
	_, err = tokenRepository.FindRefreshToken(context.Background(), "absent-token-hash")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindRefreshToken(absent) error = %v, want ErrNotFound", err)
	}

	duplicateAccess := accessToken("rolled-back-access", client.ID, user.ID, &familyID)
	duplicateRefresh := refreshToken(refresh.TokenHash, familyID, 1, client.ID, user.ID)
	if err := tokenRepository.CreatePair(context.Background(), duplicateAccess, duplicateRefresh); err == nil {
		t.Fatal("CreatePair() duplicate refresh token hash error = nil")
	}
	var accessCount int64
	if err := database.Where("token_id = ?", duplicateAccess.TokenID).Model(&model.OAuthAccessToken{}).Count(&accessCount).Error; err != nil {
		t.Fatalf("count rolled-back access token: %v", err)
	}
	if accessCount != 0 {
		t.Fatalf("rolled-back access-token count = %d, want 0", accessCount)
	}
}

func TestTokenRepositoryCreatePairRejectsInvalidFamilyAppend(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "token-family-append@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)

	t.Run("new family must start at zero", func(t *testing.T) {
		familyID := "new-family-gap"
		access := accessToken("new-family-gap-access", client.ID, user.ID, &familyID)
		refresh := refreshToken("new-family-gap-refresh", familyID, 9, client.ID, user.ID)
		err := tokenRepository.CreatePair(context.Background(), access, refresh)
		if !errors.Is(err, repository.ErrInvalidArgument) {
			t.Fatalf("CreatePair() error = %v, want ErrInvalidArgument", err)
		}
		assertTokenPairAbsent(t, database, access.TokenID, refresh.TokenHash)
	})

	t.Run("active family cannot gain another refresh", func(t *testing.T) {
		familyID := "active-family-append"
		createTokenPair(t, tokenRepository, "active-family-current", familyID, 0, client.ID, user.ID)
		access := accessToken("active-family-new-access", client.ID, user.ID, &familyID)
		refresh := refreshToken("active-family-new-refresh", familyID, 1, client.ID, user.ID)
		err := tokenRepository.CreatePair(context.Background(), access, refresh)
		if !errors.Is(err, repository.ErrInvalidArgument) {
			t.Fatalf("CreatePair() error = %v, want ErrInvalidArgument", err)
		}
		assertTokenPairAbsent(t, database, access.TokenID, refresh.TokenHash)
	})
}

func TestTokenRepositoryCreatePairRejectsMismatchedPair(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "token-mismatch@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)

	tests := []struct {
		name   string
		mutate func(*model.OAuthAccessToken, *model.OAuthRefreshToken)
	}{
		{
			name: "family",
			mutate: func(_ *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				refresh.FamilyID = "different-family"
			},
		},
		{
			name: "client",
			mutate: func(_ *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				refresh.ClientID++
			},
		},
		{
			name: "user",
			mutate: func(_ *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				refresh.UserID++
			},
		},
		{
			name: "scope",
			mutate: func(access *model.OAuthAccessToken, _ *model.OAuthRefreshToken) {
				access.Scopes = model.StringArray{"openid", "email"}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			familyID := "mismatch-" + test.name
			access := accessToken(test.name+"-access", client.ID, user.ID, &familyID)
			refresh := refreshToken(test.name+"-refresh", familyID, 0, client.ID, user.ID)
			test.mutate(access, refresh)

			if err := tokenRepository.CreatePair(context.Background(), access, refresh); err == nil {
				t.Fatal("CreatePair() error = nil, want mismatched pair rejection")
			}

			var accessCount int64
			if err := database.Model(&model.OAuthAccessToken{}).
				Where("token_id = ?", access.TokenID).
				Count(&accessCount).Error; err != nil {
				t.Fatalf("count access token: %v", err)
			}
			if accessCount != 0 {
				t.Fatalf("access-token count = %d, want 0", accessCount)
			}
		})
	}
}

func TestTokenRepositoryCreatePairRejectsInvalidScopes(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "token-invalid-scopes@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)

	tests := []struct {
		name   string
		scopes model.StringArray
	}{
		{name: "unknown", scopes: model.StringArray{"openid", "unknown"}},
		{name: "duplicate", scopes: model.StringArray{"openid", "openid"}},
		{name: "missing openid", scopes: model.StringArray{"profile"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			familyID := "invalid-scopes-" + strings.ReplaceAll(test.name, " ", "-")
			access := accessToken(familyID+"-access", client.ID, user.ID, &familyID)
			refresh := refreshToken(familyID+"-refresh", familyID, 0, client.ID, user.ID)
			access.Scopes = test.scopes
			refresh.Scopes = test.scopes

			err := tokenRepository.CreatePair(context.Background(), access, refresh)
			if !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("CreatePair() error = %v, want ErrInvalidArgument", err)
			}
			assertTokenPairAbsent(t, database, access.TokenID, refresh.TokenHash)
		})
	}
}

func TestTokenRepositoryRotateRefreshToken(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotate@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotate-family"
	createTokenPair(t, tokenRepository, "rotate-current", familyID, 0, client.ID, user.ID)

	before := time.Now().UTC()
	newAccess := accessToken("rotate-new-access", client.ID, user.ID, &familyID)
	newRefresh := refreshToken("rotate-new-refresh", familyID, 1, client.ID, user.ID)
	if _, err := tokenRepository.RotateRefreshToken(
		context.Background(),
		familyID,
		"rotate-current-refresh",
		newAccess,
		newRefresh,
	); err != nil {
		t.Fatalf("RotateRefreshToken() error = %v", err)
	}
	after := time.Now().UTC()
	assertAccessTokenUnrevoked(t, database, "rotate-current-access")
	assertRefreshTokenRevokedBetween(t, database, "rotate-current-refresh", before, after)
	assertTokenUnrevoked(t, database, "rotate-new-access", "rotate-new-refresh")
}

// A capability family's total life is capped from its origin: a rotation with a
// maxLifetime clamps the rotated expiry to origin+maxLifetime instead of sliding
// it forward, and a family whose origin predates the cap is revoked so the
// client must re-authorize.
func TestTokenRepositoryRotateRefreshTokenCapOnFamilyLifetime(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotate-cap@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotate-cap-family"

	t.Run("clamps the rotated expiry to origin+cap", func(t *testing.T) {
		createTokenPair(t, tokenRepository, "rotate-cap-in", familyID, 0, client.ID, user.ID)

		var origin model.OAuthRefreshToken
		if err := database.Where("family_id = ?", familyID).Order("sequence ASC").First(&origin).Error; err != nil {
			t.Fatalf("load family origin: %v", err)
		}

		newAccess := accessToken("rotate-cap-in-new-access", client.ID, user.ID, &familyID)
		newRefresh := refreshToken("rotate-cap-in-new-refresh", familyID, 1, client.ID, user.ID)
		// The sliding window would push the expiry well past the cap; the rotation
		// must clamp it back to the family's boundary.
		newRefresh.ExpiresAt = origin.CreatedAt.Add(30 * 24 * time.Hour)
		if _, err := tokenRepository.RotateRefreshTokenWithAuditCapped(
			context.Background(), familyID, "rotate-cap-in-refresh", newAccess, newRefresh, nil, 7*24*time.Hour,
		); err != nil {
			t.Fatalf("RotateRefreshTokenWithAuditCapped() error = %v", err)
		}

		var rotated model.OAuthRefreshToken
		if err := database.Where("token_hash = ?", "rotate-cap-in-new-refresh").First(&rotated).Error; err != nil {
			t.Fatalf("load rotated refresh: %v", err)
		}
		want := origin.CreatedAt.Add(7 * 24 * time.Hour)
		if !rotated.ExpiresAt.Equal(want) {
			t.Fatalf("rotated expiry = %v, want origin+7d %v", rotated.ExpiresAt, want)
		}
	})

	t.Run("revokes a family whose origin predates the cap", func(t *testing.T) {
		pastFamily := familyID + "-past"
		createTokenPair(t, tokenRepository, "rotate-cap-past", pastFamily, 0, client.ID, user.ID)

		// Rewind the origin to before the cap shipped while the presented token
		// stays valid: the migration shape of a pre-cap family with a longer expiry.
		if err := database.Model(&model.OAuthRefreshToken{}).
			Where("family_id = ?", pastFamily).
			Where("sequence = 0").
			Update("created_at", time.Now().Add(-8*24*time.Hour)).Error; err != nil {
			t.Fatalf("rewind family origin: %v", err)
		}

		newAccess := accessToken("rotate-cap-past-new-access", client.ID, user.ID, &pastFamily)
		newRefresh := refreshToken("rotate-cap-past-new-refresh", pastFamily, 1, client.ID, user.ID)
		_, err := tokenRepository.RotateRefreshTokenWithAuditCapped(
			context.Background(), pastFamily, "rotate-cap-past-refresh", newAccess, newRefresh, nil, 7*24*time.Hour,
		)
		if !errors.Is(err, repository.ErrTokenFamilyExpired) {
			t.Fatalf("RotateRefreshTokenWithAuditCapped() error = %v, want ErrTokenFamilyExpired", err)
		}
		// The family was revoked in the committed transaction, so the rotated pair
		// never landed.
		assertTokenPairAbsent(t, database, "rotate-cap-past-new-access", "rotate-cap-past-new-refresh")
	})
}

func TestTokenRepositoryRotateRefreshTokenRejectsInvalidInputs(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotate-invalid@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotate-invalid-family"
	createTokenPair(t, tokenRepository, "rotate-invalid-current", familyID, 0, client.ID, user.ID)

	tests := []struct {
		name        string
		mutate      func(*model.OAuthAccessToken, *model.OAuthRefreshToken)
		want        error
		currentHash string
	}{
		{
			name:        "missing current",
			want:        repository.ErrNotFound,
			currentHash: "missing-refresh-hash",
		},
		{
			name:        "family mismatch",
			currentHash: "rotate-invalid-current-refresh",
			want:        repository.ErrInvalidArgument,
			mutate: func(access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				otherFamily := "other-family"
				access.FamilyID = &otherFamily
				refresh.FamilyID = otherFamily
			},
		},
		{
			name:        "client mismatch",
			currentHash: "rotate-invalid-current-refresh",
			want:        repository.ErrInvalidArgument,
			mutate: func(access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				access.ClientID++
				refresh.ClientID++
			},
		},
		{
			name:        "user mismatch",
			currentHash: "rotate-invalid-current-refresh",
			want:        repository.ErrInvalidArgument,
			mutate: func(access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				access.UserID++
				refresh.UserID++
			},
		},
		{
			name:        "sequence mismatch",
			currentHash: "rotate-invalid-current-refresh",
			want:        repository.ErrInvalidArgument,
			mutate: func(_ *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				refresh.Sequence = 2
			},
		},
		{
			name:        "scope escalation",
			currentHash: "rotate-invalid-current-refresh",
			want:        repository.ErrInvalidArgument,
			mutate: func(access *model.OAuthAccessToken, refresh *model.OAuthRefreshToken) {
				access.Scopes = model.StringArray{"openid", "email"}
				refresh.Scopes = model.StringArray{"openid", "email"}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			access := accessToken(test.name+"-access", client.ID, user.ID, &familyID)
			refresh := refreshToken(test.name+"-refresh", familyID, 1, client.ID, user.ID)
			if test.mutate != nil {
				test.mutate(access, refresh)
			}

			_, err := tokenRepository.RotateRefreshToken(context.Background(), familyID, test.currentHash, access, refresh)
			if !errors.Is(err, test.want) {
				t.Fatalf("RotateRefreshToken() error = %v, want %v", err, test.want)
			}
			assertTokenPairAbsent(t, database, access.TokenID, refresh.TokenHash)
		})
	}
}

func TestTokenRepositoryRotateRefreshTokenReplayRevokesFamilyAndReturnsReplay(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotate-replay@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotate-replay-family"
	createTokenPair(t, tokenRepository, "rotate-replay-current", familyID, 0, client.ID, user.ID)

	oldRevokedAt := time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC)
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("token_hash = ?", "rotate-replay-current-refresh").
		Update("revoked_at", oldRevokedAt).Error; err != nil {
		t.Fatalf("pre-revoke refresh token: %v", err)
	}
	createTokenPair(t, tokenRepository, "rotate-replay-active", familyID, 1, client.ID, user.ID)
	if err := database.Model(&model.OAuthAccessToken{}).
		Where("token_id = ?", "rotate-replay-current-access").
		Update("revoked_at", oldRevokedAt).Error; err != nil {
		t.Fatalf("pre-revoke access token: %v", err)
	}

	newAccess := accessToken("rotate-replay-new-access", client.ID, user.ID, &familyID)
	newRefresh := refreshToken("rotate-replay-new-refresh", familyID, 1, client.ID, user.ID)
	beforeReplay := time.Now().UTC()
	_, err := tokenRepository.RotateRefreshToken(context.Background(), familyID, "rotate-replay-current-refresh", newAccess, newRefresh)
	if !errors.Is(err, repository.ErrTokenReplay) {
		t.Fatalf("RotateRefreshToken(replay) error = %v, want ErrTokenReplay", err)
	}
	afterReplay := time.Now().UTC()
	assertTokenPairAbsent(t, database, newAccess.TokenID, newRefresh.TokenHash)
	assertTokenRevokedAt(t, database, "rotate-replay-current-access", "rotate-replay-current-refresh", oldRevokedAt)
	assertTokenRevokedBetween(t, database, "rotate-replay-active-access", "rotate-replay-active-refresh", beforeReplay, afterReplay)
}

func TestTokenRepositoryRotateRefreshTokenReplayIgnoresMalformedReplacement(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotate-malformed-replay@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotate-malformed-replay-family"
	createTokenPair(t, tokenRepository, "rotate-malformed-replay-old", familyID, 0, client.ID, user.ID)

	oldRevokedAt := time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC)
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("token_hash = ?", "rotate-malformed-replay-old-refresh").
		Update("revoked_at", oldRevokedAt).Error; err != nil {
		t.Fatalf("pre-revoke old refresh token: %v", err)
	}
	createTokenPair(t, tokenRepository, "rotate-malformed-replay-active", familyID, 1, client.ID, user.ID)

	newAccess := accessToken("rotate-malformed-replay-new-access", client.ID, user.ID, &familyID)
	newRefresh := refreshToken("rotate-malformed-replay-new-refresh", familyID, 999, client.ID, user.ID)
	beforeReplay := time.Now().UTC()
	_, err := tokenRepository.RotateRefreshToken(
		context.Background(),
		familyID,
		"rotate-malformed-replay-old-refresh",
		newAccess,
		newRefresh,
	)
	if !errors.Is(err, repository.ErrTokenReplay) {
		t.Fatalf("RotateRefreshToken(replay) error = %v, want ErrTokenReplay", err)
	}
	assertTokenPairAbsent(t, database, newAccess.TokenID, newRefresh.TokenHash)
	assertTokenRevokedBetween(
		t,
		database,
		"rotate-malformed-replay-active-access",
		"rotate-malformed-replay-active-refresh",
		beforeReplay,
		time.Now().UTC(),
	)
}

func TestTokenRepositoryRotateRefreshTokenRejectsExpiredCurrent(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "rotate-expired@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyID := "rotate-expired-family"
	createTokenPair(t, tokenRepository, "rotate-expired-current", familyID, 0, client.ID, user.ID)

	if err := database.Exec(`
		ALTER TABLE oauth_refresh_tokens
		DROP CONSTRAINT ck_oauth_refresh_tokens_expiry
	`).Error; err != nil {
		t.Fatalf("drop refresh expiry constraint: %v", err)
	}
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("token_hash = ?", "rotate-expired-current-refresh").
		Update("expires_at", time.Now().Add(-time.Hour)).Error; err != nil {
		t.Fatalf("expire current refresh token: %v", err)
	}

	newAccess := accessToken("rotate-expired-new-access", client.ID, user.ID, &familyID)
	newRefresh := refreshToken("rotate-expired-new-refresh", familyID, 1, client.ID, user.ID)
	_, err := tokenRepository.RotateRefreshToken(context.Background(), familyID, "rotate-expired-current-refresh", newAccess, newRefresh)
	if !errors.Is(err, repository.ErrTokenExpired) {
		t.Fatalf("RotateRefreshToken(expired) error = %v, want ErrTokenExpired", err)
	}
	assertTokenPairAbsent(t, database, newAccess.TokenID, newRefresh.TokenHash)
}

func TestTokenRepositoryRevokeFamily(t *testing.T) {
	database := setupDatabase(t)
	user := createUserWithProfile(t, repository.NewUser(database), "revoke@njupt.edu.cn")
	client := createOAuthClient(t, database)
	tokenRepository := repository.NewToken(database)
	familyA := "family-a"
	familyB := "family-b"
	revokedAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	createTokenPair(t, tokenRepository, "a1", familyA, 0, client.ID, user.ID)
	if err := database.Model(&model.OAuthRefreshToken{}).
		Where("token_hash = ?", "a1-refresh").
		Update("revoked_at", revokedAt).Error; err != nil {
		t.Fatalf("revoke first family-A refresh token: %v", err)
	}
	createTokenPair(t, tokenRepository, "a2", familyA, 1, client.ID, user.ID)
	createTokenPair(t, tokenRepository, "b1", familyB, 0, client.ID, user.ID)

	if _, err := tokenRepository.RevokeFamily(context.Background(), familyA, revokedAt); err != nil {
		t.Fatalf("RevokeFamily() error = %v", err)
	}
	assertFamilyRevokedAt(t, database, familyA, revokedAt)
	assertFamilyUnrevoked(t, database, familyB)

	preservedAt := revokedAt.Add(-time.Hour)
	if err := database.Model(&model.OAuthAccessToken{}).Where("token_id = ?", "a1-access").Update("revoked_at", preservedAt).Error; err != nil {
		t.Fatalf("pre-revoke access token: %v", err)
	}
	if err := database.Model(&model.OAuthRefreshToken{}).Where("token_hash = ?", "a1-refresh").Update("revoked_at", preservedAt).Error; err != nil {
		t.Fatalf("pre-revoke refresh token: %v", err)
	}
	if _, err := tokenRepository.RevokeFamily(context.Background(), familyA, revokedAt.Add(time.Hour)); err != nil {
		t.Fatalf("second RevokeFamily() error = %v", err)
	}
	assertTokenRevokedAt(t, database, "a1-access", "a1-refresh", preservedAt)
}
