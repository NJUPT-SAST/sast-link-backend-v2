package oauth

import (
	"context"
	"errors"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
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
		wantProfile       string
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
			wantProfile:   "https://link.sast.fun/card/1",
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
			wantProfile:       "https://link.sast.fun/card/1",
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
				result.PreferredUsername != test.wantPreferred || result.Profile != test.wantProfile {
				t.Fatalf("profile claims = %+v, want name %q picture %q preferred %q profile %q",
					result, test.wantName, test.wantPicture, test.wantPreferred, test.wantProfile)
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
	if result.Profile != "https://link.sast.fun/card/1" {
		t.Fatalf("profile = %q, want the card URL regardless of the profile row", result.Profile)
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
