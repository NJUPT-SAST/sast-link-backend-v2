package oauth

import (
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

// Discovery returns the OpenID Connect Discovery 1.0 metadata document.
//
// Endpoint URLs are derived from Issuer, keeping the issuer in this document equal
// to the iss claim of every ID Token. It is a map rather than a struct because the
// document is pure protocol output with fixed spec key names.
func (s Service) Discovery() map[string]any {
	base := strings.TrimRight(strings.TrimSpace(s.Issuer), "/")
	return map[string]any{
		"issuer":                 base,
		"authorization_endpoint": base + "/oauth/authorize",
		"token_endpoint":         base + "/oauth/token",
		"userinfo_endpoint":      base + "/userinfo",
		"jwks_uri":               base + "/.well-known/jwks.json",
		"revocation_endpoint":    base + "/oauth/revoke",
		"scopes_supported": []string{
			scope.OpenID, scope.Profile, scope.Email,
			// The capability scopes are requestable by this provider, so standard OIDC
			// clients validating against this list need them advertised.
			scope.AdminRead, scope.AdminWrite, scope.UserRead, scope.UserWrite,
		},
		"response_types_supported": []string{responseTypeCode},
		"grant_types_supported": []string{
			grantTypeAuthorizationCode,
			grantTypeRefreshToken,
		},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		// "none" covers public clients authenticating by PKCE alone; confidential
		// clients post their secret. No Basic support.
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		// role is this provider's own claim, not an OIDC one, advertised here because a
		// relying party has no other way to discover it; it rides the profile scope.
		// auth_time is deliberately absent even though the ID Token carries it: the
		// value could only be the consent instant, not when the user authenticated.
		// TODO(auth_time): persisting a real authentication timestamp at login would
		// let this entry be advertised.
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "nonce",
			"name", "picture", "preferred_username", "role",
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
