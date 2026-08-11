package oauth

import (
	"context"
	"errors"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

func stringPtr(value string) *string { return &value }

func seedCard(h *harness) {
	h.profiles.byUserID[1] = &repository.PublicCard{
		ID:       1,
		Nickname: stringPtr("三三"),
		Avatar:   stringPtr("https://cos.example.test/avatar/1.jpg"),
	}
}

// The scope gate is the whole contract here: a token limited to openid must yield
// sub alone, even though the same account would supply more to a broader token.
func TestUserInfoFiltersClaimsByScope(t *testing.T) {
	tests := []struct {
		name              string
		scopes            []string
		wantName          string
		wantPicture       string
		wantPreferred     string
		wantEmail         string
		wantEmailVerified bool
		wantUpdatedAt     bool
	}{
		{name: "openid only", scopes: []string{"openid"}},
		{
			name:          "openid profile",
			scopes:        []string{"openid", "profile"},
			wantName:      "张三",
			wantPicture:   "https://cos.example.test/avatar/1.jpg",
			wantPreferred: "三三",
			wantUpdatedAt: true,
		},
		{
			name:              "openid email",
			scopes:            []string{"openid", "email"},
			wantEmail:         "b24040101@njupt.edu.cn",
			wantEmailVerified: true,
		},
		{
			name:              "all scopes",
			scopes:            []string{"openid", "profile", "email"},
			wantName:          "张三",
			wantPicture:       "https://cos.example.test/avatar/1.jpg",
			wantPreferred:     "三三",
			wantEmail:         "b24040101@njupt.edu.cn",
			wantEmailVerified: true,
			wantUpdatedAt:     true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			seedCard(h)

			result, err := h.service.UserInfo(context.Background(), UserInfoInput{UserID: 1, Scopes: test.scopes})
			if err != nil {
				t.Fatalf("UserInfo() error = %v", err)
			}
			if result.Subject != "1" {
				t.Fatalf("sub = %q, want the user ID; it must always ship", result.Subject)
			}
			if result.Name != test.wantName || result.Picture != test.wantPicture ||
				result.PreferredUsername != test.wantPreferred {
				t.Fatalf("profile claims = %+v, want name %q picture %q preferred %q",
					result, test.wantName, test.wantPicture, test.wantPreferred)
			}
			if result.Email != test.wantEmail {
				t.Fatalf("email = %q, want %q", result.Email, test.wantEmail)
			}
			switch {
			case test.wantEmailVerified && (result.EmailVerified == nil || !*result.EmailVerified):
				t.Fatalf("email_verified = %v, want true", result.EmailVerified)
			case !test.wantEmailVerified && result.EmailVerified != nil:
				t.Fatalf("email_verified = %v, want omitted without the email scope", *result.EmailVerified)
			}
			if (result.UpdatedAt != 0) != test.wantUpdatedAt {
				t.Fatalf("updated_at = %d, want present = %v", result.UpdatedAt, test.wantUpdatedAt)
			}
		})
	}
}

// preferred_username falls back to the real name so a relying party always has
// something displayable, and an account with no profile row is not an error.
// role rides the profile scope. It is this provider's own claim rather than an OIDC
// one, so it needs its own assertion that the gate applies to it too — a claim that
// leaked without its scope would hand every openid-only client the user's standing.
func TestUserInfoGatesRoleByProfileScope(t *testing.T) {
	for _, test := range []struct {
		name     string
		scopes   []string
		wantRole string
	}{
		{name: "openid only", scopes: []string{"openid"}},
		{name: "openid email", scopes: []string{"openid", "email"}},
		{name: "openid profile", scopes: []string{"openid", "profile"}, wantRole: string(model.UserRoleMember)},
		{name: "all scopes", scopes: []string{"openid", "profile", "email"}, wantRole: string(model.UserRoleMember)},
		// An admin scope contributes no claim, so it must not smuggle role in either.
		{name: "openid admin:read", scopes: []string{"openid", scope.AdminRead}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			result, err := h.service.UserInfo(context.Background(), UserInfoInput{UserID: 1, Scopes: test.scopes})
			if err != nil {
				t.Fatalf("UserInfo() error = %v", err)
			}
			if result.Role != test.wantRole {
				t.Fatalf("role = %q, want %q", result.Role, test.wantRole)
			}
		})
	}
}

// The role reported is the database's, not the requesting token's. A token's own role
// claim is a signing-time snapshot that survives a demotion, so reporting it would
// tell a relying party the user still holds a role this service has already revoked.
func TestUserInfoRoleTracksTheDatabaseRow(t *testing.T) {
	h := newHarness(t)
	h.users.byID[1].Role = model.UserRoleAdmin

	result, err := h.service.UserInfo(context.Background(), UserInfoInput{
		UserID: 1, Scopes: []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("UserInfo() error = %v", err)
	}
	if result.Role != string(model.UserRoleAdmin) {
		t.Fatalf("role = %q, want the current database role %q", result.Role, model.UserRoleAdmin)
	}
}

func TestUserInfoFallsBackWithoutProfileRow(t *testing.T) {
	h := newHarness(t)

	result, err := h.service.UserInfo(context.Background(), UserInfoInput{UserID: 1, Scopes: []string{"openid", "profile"}})
	if err != nil {
		t.Fatalf("UserInfo() error = %v", err)
	}
	if result.PreferredUsername != "张三" || result.Name != "张三" {
		t.Fatalf("claims = %+v, want the real name as the preferred_username fallback", result)
	}
	if result.Picture != "" {
		t.Fatalf("picture = %q, want empty without a profile row", result.Picture)
	}
}

// A blank nickname must not win over the real name; it would render as an empty
// display name on the relying party.
func TestUserInfoIgnoresBlankNickname(t *testing.T) {
	h := newHarness(t)
	h.profiles.byUserID[1] = &repository.PublicCard{ID: 1, Nickname: stringPtr("   ")}

	result, err := h.service.UserInfo(context.Background(), UserInfoInput{UserID: 1, Scopes: []string{"openid", "profile"}})
	if err != nil {
		t.Fatalf("UserInfo() error = %v", err)
	}
	if result.PreferredUsername != "张三" {
		t.Fatalf("preferred_username = %q, want the real name", result.PreferredUsername)
	}
}

// A token limited to openid or email must not touch the profile table at all.
func TestUserInfoSkipsProfileLookupWithoutProfileScope(t *testing.T) {
	h := newHarness(t)
	h.profiles.err = errors.New("profile read must not be attempted")

	if _, err := h.service.UserInfo(context.Background(), UserInfoInput{UserID: 1, Scopes: []string{"openid", "email"}}); err != nil {
		t.Fatalf("UserInfo() error = %v, want the profile lookup skipped", err)
	}
}

func TestUserInfoRejectsInvalidPrincipalAndScopes(t *testing.T) {
	h := newHarness(t)

	tests := []struct {
		name   string
		input  UserInfoInput
		before func()
	}{
		{name: "no principal", input: UserInfoInput{UserID: 0, Scopes: []string{"openid"}}},
		{name: "scopes without openid", input: UserInfoInput{UserID: 1, Scopes: []string{"profile"}}},
		{name: "empty scopes", input: UserInfoInput{UserID: 1}},
		{name: "unknown user", input: UserInfoInput{UserID: 999, Scopes: []string{"openid"}}},
		{
			name:   "deleted account",
			input:  UserInfoInput{UserID: 1, Scopes: []string{"openid"}},
			before: func() { h.users.byID[1].State = model.UserStateDeleted },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.before != nil {
				test.before()
			}
			_, err := h.service.UserInfo(context.Background(), test.input)
			requireOAuthError(t, err, ErrorInvalidToken)
		})
	}
}

func TestUserInfoSurfacesProfileFailure(t *testing.T) {
	h := newHarness(t)
	h.profiles.err = errors.New("database down")

	_, err := h.service.UserInfo(context.Background(), UserInfoInput{UserID: 1, Scopes: []string{"openid", "profile"}})
	requireOAuthError(t, err, ErrorServerError)
}
