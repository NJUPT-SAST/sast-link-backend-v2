package oauth

import (
	"reflect"
	"testing"
)

// OIDC requires the issuer in this document to equal the iss claim of every ID
// Token, and the endpoint URLs to be absolute. Deriving them from one Issuer
// value is what keeps those two from drifting apart.
func TestDiscoveryDerivesEndpointsFromIssuer(t *testing.T) {
	h := newHarness(t)

	document := h.service.Discovery()

	// #nosec G101 -- public OIDC endpoint URLs, not credentials. The "token_endpoint"
	// key name is what trips the detector.
	want := map[string]string{
		"issuer":                 "https://link.sast.fun/v2",
		"authorization_endpoint": "https://link.sast.fun/v2/oauth/authorize",
		"token_endpoint":         "https://link.sast.fun/v2/oauth/token",
		"userinfo_endpoint":      "https://link.sast.fun/v2/userinfo",
		"jwks_uri":               "https://link.sast.fun/v2/.well-known/jwks.json",
		"revocation_endpoint":    "https://link.sast.fun/v2/oauth/revoke",
	}
	for key, expected := range want {
		if got, _ := document[key].(string); got != expected {
			t.Fatalf("%s = %q, want %q", key, got, expected)
		}
	}
	// The issuer here must match what the JWT manager signs into iss, or relying
	// parties will reject every ID Token.
	if document["issuer"] != h.service.JWT.Issuer {
		t.Fatalf("discovery issuer = %v, JWT issuer = %q; want equal", document["issuer"], h.service.JWT.Issuer)
	}
}

func TestDiscoveryTrailingSlashIssuer(t *testing.T) {
	h := newHarness(t)
	h.service.Issuer = "https://link.sast.fun/v2/"

	document := h.service.Discovery()
	if got := document["token_endpoint"]; got != "https://link.sast.fun/v2/oauth/token" {
		t.Fatalf("token_endpoint = %v, want no doubled slash", got)
	}
}

// The advertised capabilities must match what the implementation actually does:
// a relying party that trusts this document and gets refused has no recourse.
func TestDiscoveryAdvertisesOnlySupportedCapabilities(t *testing.T) {
	h := newHarness(t)
	document := h.service.Discovery()

	assertStrings := func(key string, want []string) {
		t.Helper()
		got, ok := document[key].([]string)
		if !ok {
			t.Fatalf("%s = %v, want []string", key, document[key])
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s = %v, want %v", key, got, want)
		}
	}
	assertStrings("scopes_supported", []string{"openid", "profile", "email", "admin:read", "admin:write", "user:read", "user:write"})
	assertStrings("response_types_supported", []string{"code"})
	assertStrings("grant_types_supported", []string{"authorization_code", "refresh_token"})
	assertStrings("id_token_signing_alg_values_supported", []string{"EdDSA"})
	// S256-only, matching the V002 database constraint and the protocol layer.
	assertStrings("code_challenge_methods_supported", []string{"S256"})
	// "none" is for public clients authenticating by PKCE; there is no Basic support.
	assertStrings("token_endpoint_auth_methods_supported", []string{"none", "client_secret_post"})
	assertStrings("subject_types_supported", []string{"public"})

	for _, key := range []string{"request_parameter_supported", "request_uri_parameter_supported", "claims_parameter_supported"} {
		if supported, _ := document[key].(bool); supported {
			t.Fatalf("%s = true, but the implementation does not support it", key)
		}
	}
}

// Every claim the document lists must be one the ID Token or UserInfo can emit, and
// every emitted claim must be listed — except the ones deliberately withheld below.
func TestDiscoveryClaimsMatchIssuedClaims(t *testing.T) {
	h := newHarness(t)
	claims, ok := h.service.Discovery()["claims_supported"].([]string)
	if !ok {
		t.Fatal("claims_supported is not a []string")
	}
	emitted := map[string]bool{
		"sub": true, "iss": true, "aud": true, "exp": true, "iat": true,
		"nonce": true, "name": true, "picture": true,
		"preferred_username": true, "email": true,
		"email_verified": true, "updated_at": true,
		// role is this provider's own claim, under the profile scope.
		"role": true,
	}
	// auth_time is neither issued nor advertised: no code path records a truthful
	// authentication instant, so the token carries no such claim and the discovery
	// list must not invite a relying party to depend on one.
	withheld := map[string]bool{}

	for _, claim := range claims {
		if !emitted[claim] {
			t.Fatalf("claims_supported advertises %q, which nothing issues", claim)
		}
		if withheld[claim] {
			t.Fatalf("claims_supported advertises %q, which is deliberately withheld", claim)
		}
	}
	if len(claims) != len(emitted)-len(withheld) {
		t.Fatalf("claims_supported has %d entries, want %d (%d issued less %d withheld)",
			len(claims), len(emitted)-len(withheld), len(emitted), len(withheld))
	}
}

func TestJWKSExposesActiveKey(t *testing.T) {
	h := newHarness(t)

	keys, ok := h.service.JWKS()["keys"].([]map[string]string)
	if !ok {
		t.Fatalf("keys = %v, want a JWK list", h.service.JWKS()["keys"])
	}
	if len(keys) != 1 {
		t.Fatalf("keys = %d, want the single active key", len(keys))
	}
	key := keys[0]
	if key["kid"] != "active" || key["alg"] != "EdDSA" || key["kty"] != "OKP" || key["use"] != "sig" {
		t.Fatalf("key = %v, want the active EdDSA signing key", key)
	}
	// A private exponent in a public key set would be a key disclosure.
	for _, forbidden := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, present := key[forbidden]; present {
			t.Fatalf("JWKS exposes private key material %q", forbidden)
		}
	}
}

// A service without a signing key must still answer with a well-formed, empty set
// rather than a nil that would serialize as JSON null.
func TestJWKSEmptyWithoutManager(t *testing.T) {
	document := Service{}.JWKS()
	keys, ok := document["keys"].([]any)
	if !ok || len(keys) != 0 {
		t.Fatalf("keys = %v, want an empty list", document["keys"])
	}
}
