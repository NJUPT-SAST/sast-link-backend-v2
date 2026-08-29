package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

// IDTokenClaims are the OIDC ID Token claims issued by SAST Link.
//
// Every scope-gated claim is a pointer or omitempty, so a claim absent from the
// granted scopes is absent from the token rather than present-and-empty.
type IDTokenClaims struct {
	// Nonce echoes the authorization request's nonce verbatim so the relying party
	// can bind this token to its own request. Absent when the request had none.
	Nonce string `json:"nonce,omitempty"`

	// profile scope.
	Name              string `json:"name,omitempty"`
	Picture           string `json:"picture,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	// Role is this service's own claim, not an OIDC one, carried under the profile
	// scope. It is always the user's *current* role, read from the database row when
	// the token is issued — never the role claim of whatever access token asked for
	// it, which is a snapshot that survives a demotion. A relying party must still
	// treat it as a display hint, not the basis of an authorization decision.
	Role string `json:"role,omitempty"`

	// email scope. EmailVerified is a pointer so it can be omitted entirely
	// without the email scope, rather than defaulting to a misleading false.
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`

	jwt.RegisteredClaims
}

// IDTokenSubjectClaims carries the user attributes an ID Token may expose. The
// signer selects among them by granted scope, so callers pass everything they
// have and never decide the scope mapping themselves.
type IDTokenSubjectClaims struct {
	Name              string
	Picture           string
	PreferredUsername string
	UpdatedAt         time.Time
	Email             string
	// Role is the user's current role from the database row.
	Role string
}

// IDTokenInput contains data required to issue an ID Token.
type IDTokenInput struct {
	// Subject is the user ID as a string, matching the access token's sub.
	Subject string
	// ClientID is the OAuth client_id and becomes the sole audience. Unlike an
	// access token, an ID Token is addressed to the client, not to this service.
	ClientID string
	// Scopes must already be normalized-able; openid is required.
	Scopes []string
	Nonce  string
	TTL    time.Duration
	// Claims holds every user attribute an ID Token could carry; the signer emits
	// only those the granted scopes allow.
	Claims IDTokenSubjectClaims
}

// SignIDToken signs an OIDC ID Token with the active EdDSA key.
//
// Deliberately separate from SignAccessToken: an ID Token's audience is the
// client_id, not this service, so signing it through the access-token path could
// ship ID Tokens this service would accept as its own bearer credentials.
func (m JWTManager) SignIDToken(input IDTokenInput) (string, error) {
	normalized, err := scope.Normalize(input.Scopes)
	if err != nil {
		return "", ErrInvalidInput
	}
	// Admin scopes carry no claim, so they are dropped before the mapping rather
	// than left for applyIDTokenScopeClaims to skip by omission.
	granted := scope.ClaimScopes(normalized)
	if m.Issuer == "" || strings.TrimSpace(input.Subject) == "" ||
		strings.TrimSpace(input.ClientID) == "" || input.TTL <= 0 ||
		m.Active.KID == "" || m.Active.Private == nil {
		return "", ErrInvalidInput
	}
	issuedAt := now(m.Clock).UTC()
	claims := IDTokenClaims{
		Nonce: input.Nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.Issuer,
			Subject:   input.Subject,
			Audience:  jwt.ClaimStrings{input.ClientID},
			ExpiresAt: jwt.NewNumericDate(issuedAt.Add(input.TTL)),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
		},
	}
	applyIDTokenScopeClaims(&claims, granted, input.Claims)

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = m.Active.KID
	signed, err := token.SignedString(m.Active.Private)
	if err != nil {
		return "", fmt.Errorf("sign ID token: %w", err)
	}
	return signed, nil
}

// applyIDTokenScopeClaims copies subject attributes into the claims the granted
// scopes permit, per PRD §4.11's scope-to-claims mapping. openid contributes sub
// alone, which the registered claims already carry.
func applyIDTokenScopeClaims(claims *IDTokenClaims, granted []string, subject IDTokenSubjectClaims) {
	for _, name := range granted {
		switch name {
		case scope.Profile:
			claims.Name = subject.Name
			claims.Picture = subject.Picture
			claims.PreferredUsername = subject.PreferredUsername
			claims.Role = subject.Role
			if !subject.UpdatedAt.IsZero() {
				claims.UpdatedAt = subject.UpdatedAt.UTC().Unix()
			}
		case scope.Email:
			claims.Email = subject.Email
			// Fixed true: an account exists only after its address passed the
			// registration verification code, so a bound email is verified by
			// construction.
			verified := true
			claims.EmailVerified = &verified
		}
	}
}
