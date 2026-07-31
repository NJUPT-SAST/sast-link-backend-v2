package config

import (
	"strings"
	"testing"
	"time"
)

// enableGitHubLogin sets a complete, valid GitHub provider configuration.
func enableGitHubLogin(t *testing.T) {
	t.Helper()
	t.Setenv("OAUTH_GITHUB_ENABLED", "true")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "gh-client")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "gh-secret")
	t.Setenv("OAUTH_GITHUB_REDIRECT_URI", "https://link.example.test/v2/oauth/github/callback")
	t.Setenv("OAUTH_LOGIN_REDIRECTS", "https://link.example.test/callback")
}

// enableLarkLogin sets a complete, valid Lark provider configuration, tenant key
// included.
func enableLarkLogin(t *testing.T) {
	t.Helper()
	t.Setenv("OAUTH_FEISHU_ENABLED", "true")
	t.Setenv("OAUTH_FEISHU_CLIENT_ID", "cli_app")
	t.Setenv("OAUTH_FEISHU_CLIENT_SECRET", "app-secret")
	t.Setenv("OAUTH_FEISHU_REDIRECT_URI", "https://link.example.test/v2/oauth/lark/callback")
	t.Setenv("OAUTH_FEISHU_TENANT_KEY", "sast-tenant")
	t.Setenv("OAUTH_LOGIN_REDIRECTS", "https://link.example.test/callback")
}

// Most deployments run neither provider. Demanding credentials for an unused one
// would make the service unstartable for no benefit, so the blank values that
// .env.example ships with must validate.
func TestValidateAPIAuthAllowsBothProvidersDisabled(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OAuthGitHubEnabled || cfg.OAuthLarkEnabled {
		t.Fatal("providers default to enabled, want disabled")
	}
	if validateErr := cfg.ValidateAPIAuth(); validateErr != nil {
		t.Fatalf("ValidateAPIAuth() error = %v, want nil with no provider enabled", validateErr)
	}
}

// A disabled provider's blank credentials must not be validated even when the
// other provider is on, or enabling GitHub would force a deployment to invent
// Lark credentials it never uses.
func TestValidateAPIAuthIgnoresDisabledProviderCredentials(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	enableGitHubLogin(t)
	// Lark stays off with everything blank, including its tenant key.

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if validateErr := cfg.ValidateAPIAuth(); validateErr != nil {
		t.Fatalf("ValidateAPIAuth() error = %v, want nil with only GitHub enabled", validateErr)
	}
}

func TestValidateAPIAuthAcceptsBothProvidersEnabled(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	enableGitHubLogin(t)
	enableLarkLogin(t)
	t.Setenv("OAUTH_LOGIN_ERROR_REDIRECT", "https://link.example.test/oauth/error")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if validateErr := cfg.ValidateAPIAuth(); validateErr != nil {
		t.Fatalf("ValidateAPIAuth() error = %v, want nil", validateErr)
	}
	if !cfg.OAuthGitHubEnabled || !cfg.OAuthLarkEnabled {
		t.Fatalf("enabled flags = %v/%v, want both true", cfg.OAuthGitHubEnabled, cfg.OAuthLarkEnabled)
	}
	// The FEISHU-spelled variables must land on the Lark fields the service reads;
	// a mismatch here would leave Lark unconfigured while validation passed.
	if cfg.OAuthLarkClientID != "cli_app" || cfg.OAuthLarkTenantKey != "sast-tenant" {
		t.Fatalf("Lark config = %q/%q, want cli_app/sast-tenant",
			cfg.OAuthLarkClientID, cfg.OAuthLarkTenantKey)
	}
}

// An enabled provider with missing credentials must fail at boot. Otherwise the
// failure surfaces as a confusing provider rejection for the first user who tries
// to log in.
func TestValidateAPIAuthRejectsIncompleteEnabledGitHub(t *testing.T) {
	for _, test := range []struct{ name, key, value, want string }{
		{"missing client id", "OAUTH_GITHUB_CLIENT_ID", "", "OAUTH_GITHUB_CLIENT_ID is required"},
		{"blank client id", "OAUTH_GITHUB_CLIENT_ID", "   ", "OAUTH_GITHUB_CLIENT_ID is required"},
		{"missing secret", "OAUTH_GITHUB_CLIENT_SECRET", "", "OAUTH_GITHUB_CLIENT_SECRET is required"},
		{"blank secret", "OAUTH_GITHUB_CLIENT_SECRET", "   ", "OAUTH_GITHUB_CLIENT_SECRET is required"},
		{"relative redirect", "OAUTH_GITHUB_REDIRECT_URI", "/oauth/callback", "OAUTH_GITHUB_REDIRECT_URI must be an absolute http(s) URL"},
		{"missing redirect", "OAUTH_GITHUB_REDIRECT_URI", "", "OAUTH_GITHUB_REDIRECT_URI must be an absolute http(s) URL"},
		{"non-http scheme", "OAUTH_GITHUB_REDIRECT_URI", "ftp://link.example.test/cb", "OAUTH_GITHUB_REDIRECT_URI must be an absolute http(s) URL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			enableGitHubLogin(t)
			t.Setenv(test.key, test.value)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateAPIAuth() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateAPIAuthRejectsIncompleteEnabledLark(t *testing.T) {
	for _, test := range []struct{ name, key, value, want string }{
		{"missing app id", "OAUTH_FEISHU_CLIENT_ID", "", "OAUTH_FEISHU_CLIENT_ID is required"},
		{"missing secret", "OAUTH_FEISHU_CLIENT_SECRET", "", "OAUTH_FEISHU_CLIENT_SECRET is required"},
		{"relative redirect", "OAUTH_FEISHU_REDIRECT_URI", "/oauth/callback", "OAUTH_FEISHU_REDIRECT_URI must be an absolute http(s) URL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			enableLarkLogin(t)
			t.Setenv(test.key, test.value)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateAPIAuth() error = %v, want %q", err, test.want)
			}
		})
	}
}

// PRD §4.5 limits Lark login to the SAST enterprise. An empty tenant key disables
// that gate in the provider client, so a deployment would accept logins from every
// Lark tenant with nothing looking wrong — the one outcome the gate exists to
// prevent. It therefore cannot be optional.
func TestValidateAPIAuthRequiresLarkTenantKey(t *testing.T) {
	for _, value := range []string{"", "   "} {
		t.Run("tenant key "+value, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			enableLarkLogin(t)
			t.Setenv("OAUTH_FEISHU_TENANT_KEY", value)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), "OAUTH_FEISHU_TENANT_KEY is required") {
				t.Fatalf("ValidateAPIAuth() error = %v, want tenant key validation", err)
			}
		})
	}
}

// The tenant key is only demanded when Lark is actually on: a GitHub-only
// deployment has no tenant to name.
func TestValidateAPIAuthDoesNotRequireTenantKeyWithLarkDisabled(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	enableGitHubLogin(t)
	t.Setenv("OAUTH_FEISHU_TENANT_KEY", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if validateErr := cfg.ValidateAPIAuth(); validateErr != nil {
		t.Fatalf("ValidateAPIAuth() error = %v, want nil", validateErr)
	}
}

// The allow-list is shared by both providers, and an empty one leaves every
// callback with no valid redirect. Without this check the service would boot and
// fail only once a user completed a provider login.
func TestValidateAPIAuthRequiresRedirectAllowListWhenEnabled(t *testing.T) {
	for _, test := range []struct {
		name   string
		enable func(*testing.T)
	}{
		{"github only", enableGitHubLogin},
		{"lark only", enableLarkLogin},
	} {
		t.Run(test.name, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			test.enable(t)
			t.Setenv("OAUTH_LOGIN_REDIRECTS", "")

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), "OAUTH_LOGIN_REDIRECTS is required") {
				t.Fatalf("ValidateAPIAuth() error = %v, want allow-list validation", err)
			}
		})
	}
}

// A relative or non-http entry could never match a real callback redirect, so it
// is a misconfiguration that must fail loudly rather than silently reject every
// login attempt at runtime.
func TestValidateAPIAuthRejectsNonAbsoluteRedirectAllowListEntries(t *testing.T) {
	for _, value := range []string{
		"/callback",
		"link.example.test/callback",
		"ftp://link.example.test/callback",
	} {
		t.Run(value, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			enableGitHubLogin(t)
			// A valid entry first, so the failure is attributable to the second.
			t.Setenv("OAUTH_LOGIN_REDIRECTS", "https://link.example.test/callback,"+value)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), "OAUTH_LOGIN_REDIRECTS entries must be absolute") {
				t.Fatalf("ValidateAPIAuth() error = %v, want allow-list entry validation for %q", err, value)
			}
		})
	}
}

func TestValidateAPIAuthAcceptsMultipleRedirectAllowListEntries(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	enableGitHubLogin(t)
	t.Setenv("OAUTH_LOGIN_REDIRECTS",
		"https://link.example.test/callback,http://localhost:3000/oauth/callback")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if validateErr := cfg.ValidateAPIAuth(); validateErr != nil {
		t.Fatalf("ValidateAPIAuth() error = %v, want nil", validateErr)
	}
	if len(cfg.OAuthLoginRedirects) != 2 {
		t.Fatalf("OAuthLoginRedirects = %#v, want 2 entries", cfg.OAuthLoginRedirects)
	}
	// The first entry doubles as the default redirect for a login started without
	// one, so its position is load-bearing.
	if cfg.OAuthLoginRedirects[0] != "https://link.example.test/callback" {
		t.Fatalf("first entry = %q, want the configured default",
			cfg.OAuthLoginRedirects[0])
	}
}

// The error page is optional — a failed callback falls back to the JSON envelope
// when it is unset — but a malformed value would redirect a browser nowhere
// useful, so it is validated when present.
func TestValidateAPIAuthErrorRedirectIsOptionalButValidated(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")
	enableGitHubLogin(t)
	t.Setenv("OAUTH_LOGIN_ERROR_REDIRECT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if validateErr := cfg.ValidateAPIAuth(); validateErr != nil {
		t.Fatalf("ValidateAPIAuth() error = %v, want nil for an unset error page", validateErr)
	}

	t.Setenv("OAUTH_LOGIN_ERROR_REDIRECT", "not-a-url")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	err = cfg.ValidateAPIAuth()
	if err == nil || !strings.Contains(err.Error(), "OAUTH_LOGIN_ERROR_REDIRECT must be an absolute") {
		t.Fatalf("ValidateAPIAuth() error = %v, want error redirect validation", err)
	}
}

// These three TTLs bound the one-time values the flow depends on. A non-positive
// value would make SetOneTime write a key with no expiry semantics the flow
// expects, so they are checked regardless of which provider is enabled.
func TestValidateAPIAuthRejectsNonPositiveOAuthLoginTTLs(t *testing.T) {
	for _, test := range []struct{ key, value, want string }{
		{"OAUTH_LOGIN_STATE_TTL", "0", "OAUTH_LOGIN_STATE_TTL must be positive"},
		{"OAUTH_LOGIN_STATE_TTL", "-1m", "OAUTH_LOGIN_STATE_TTL must be positive"},
		{"OAUTH_LOGIN_REGISTRATION_STATE_TTL", "0", "OAUTH_LOGIN_REGISTRATION_STATE_TTL must be positive"},
		{"OAUTH_LOGIN_CODE_TTL", "0", "OAUTH_LOGIN_CODE_TTL must be positive"},
		{"OAUTH_LOGIN_CODE_TTL", "-30s", "OAUTH_LOGIN_CODE_TTL must be positive"},
	} {
		t.Run(test.key+"="+test.value, func(t *testing.T) {
			setConfigEnv(t, "user", "pass", "db")
			t.Setenv(test.key, test.value)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.ValidateAPIAuth()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateAPIAuth() error = %v, want %q", err, test.want)
			}
		})
	}
}

// The defaults must match the PRD's §6 key table, since a deployment that sets
// none of these inherits them.
func TestOAuthLoginTTLDefaultsMatchThePRD(t *testing.T) {
	setConfigEnv(t, "user", "pass", "db")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OAuthLoginStateTTL != 10*time.Minute {
		t.Errorf("OAuthLoginStateTTL = %s, want 10m", cfg.OAuthLoginStateTTL)
	}
	if cfg.OAuthLoginRegistrationStateTTL != 15*time.Minute {
		t.Errorf("OAuthLoginRegistrationStateTTL = %s, want 15m", cfg.OAuthLoginRegistrationStateTTL)
	}
	if cfg.OAuthLoginCodeTTL != time.Minute {
		t.Errorf("OAuthLoginCodeTTL = %s, want 60s", cfg.OAuthLoginCodeTTL)
	}
}
