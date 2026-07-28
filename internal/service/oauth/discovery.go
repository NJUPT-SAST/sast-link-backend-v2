package oauth

import (
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

// Discovery returns the OpenID Connect Discovery 1.0 metadata document.
//
// Endpoint URLs are derived from Issuer rather than configured separately, which
// is what keeps them from drifting: OIDC requires the issuer in this document to
// equal the iss claim of every ID Token, and both now come from the same value.
//
// The document is a map rather than a struct because it is pure protocol output
// with no internal consumer, and the key names are fixed by the spec.
func (s Service) Discovery() map[string]any {
	base := strings.TrimRight(strings.TrimSpace(s.Issuer), "/")
	return map[string]any{
		"issuer":                   base,
		"authorization_endpoint":   base + "/oauth/authorize",
		"token_endpoint":           base + "/oauth/token",
		"userinfo_endpoint":        base + "/userinfo",
		"jwks_uri":                 base + "/.well-known/jwks.json",
		"revocation_endpoint":      base + "/oauth/revoke",
		"scopes_supported":         []string{scope.OpenID, scope.Profile, scope.Email},
		"response_types_supported": []string{responseTypeCode},
		"grant_types_supported": []string{
			grantTypeAuthorizationCode,
			grantTypeRefreshToken,
		},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		// "none" covers public clients authenticating by PKCE alone; confidential
		// clients post their secret. There is no Basic support, matching the contract.
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"name", "picture", "preferred_username", "profile",
			"email", "email_verified", "updated_at",
		},
		"code_challenge_methods_supported": []string{pkceMethodS256},
		"response_modes_supported":         []string{"query"},
		"claim_types_supported":            []string{"normal"},
		"request_parameter_supported":      false,
		"request_uri_parameter_supported":  false,
		"claims_parameter_supported":       false,
	}
}

// JWKS returns the public key set used to verify issued JWTs.
func (s Service) JWKS() map[string]any {
	if s.JWT == nil {
		return map[string]any{"keys": []any{}}
	}
	return s.JWT.JWKS()
}
