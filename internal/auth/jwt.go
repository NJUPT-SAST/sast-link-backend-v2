package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

const jwtAlgEdDSA = "EdDSA"

// JWTKeyPair is an Ed25519 key pair identified by kid.
type JWTKeyPair struct {
	KID     string
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// TokenClaims are access-token claims used by SAST Link.
//
// AZP (OIDC "authorized party") names the client the token was issued to. Every
// access token shares one audience — this service — because the internal API is
// the resource server in both cases. The audience therefore cannot distinguish a
// token minted for a third-party client from a first-party session token, and
// without that distinction a third-party token authenticates on the internal
// surface: an openid-only grant would reach PUT /user/profile and the email
// binding endpoints, which is account takeover. AZP is what the internal
// middleware pins so only the built-in client's tokens are accepted there.
//
// Omitted (empty) means a first-party session token, so tokens signed before this
// claim existed keep working; those are only ever issued to the built-in client.
type TokenClaims struct {
	Role         string `json:"role"`
	State        string `json:"state"`
	TokenVersion int    `json:"token_version"`
	Scope        string `json:"scope"`
	AZP          string `json:"azp,omitempty"`
	jwt.RegisteredClaims
}

// UnmarshalJSON records whether token_version was present so zero remains valid.
func (c *TokenClaims) UnmarshalJSON(data []byte) error {
	type tokenClaimsAlias TokenClaims
	var raw struct {
		TokenVersion *int `json:"token_version"`
		*tokenClaimsAlias
	}
	raw.tokenClaimsAlias = (*tokenClaimsAlias)(c)
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.TokenVersion == nil {
		return ErrInvalidToken
	}
	c.TokenVersion = *raw.TokenVersion
	return nil
}

// TokenInput contains data required to issue an access token.
type TokenInput struct {
	Subject      string
	JTI          string
	Role         string
	State        string
	TokenVersion int
	Scopes       []string
	TTL          time.Duration
	NotBefore    time.Time
	// AuthorizedParty becomes the azp claim: the client_id this token was issued
	// to. Leave empty only for first-party session tokens.
	AuthorizedParty string
}

// JWTManager signs with the active key and verifies with active plus previous keys.
type JWTManager struct {
	Issuer   string
	Audience []string
	Active   JWTKeyPair
	Previous []JWTKeyPair
	Clock    Clock
}

// SignAccessToken signs an EdDSA JWT with the active private key and kid.
func (m JWTManager) SignAccessToken(input TokenInput) (string, error) {
	scopeClaim, err := scope.Claim(input.Scopes)
	if err != nil {
		return "", ErrInvalidInput
	}
	if m.Issuer == "" || input.Subject == "" || strings.TrimSpace(input.JTI) == "" || strings.TrimSpace(input.Role) == "" || strings.TrimSpace(input.State) == "" ||
		input.TokenVersion < 0 || len(m.Audience) == 0 || input.TTL <= 0 || m.Active.KID == "" || m.Active.Private == nil {
		return "", ErrInvalidInput
	}
	issuedAt := now(m.Clock).UTC()
	notBefore := input.NotBefore.UTC()
	if notBefore.IsZero() {
		notBefore = issuedAt
	}
	claims := TokenClaims{
		Role:         input.Role,
		State:        input.State,
		TokenVersion: input.TokenVersion,
		Scope:        scopeClaim,
		AZP:          strings.TrimSpace(input.AuthorizedParty),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.Issuer,
			Subject:   input.Subject,
			Audience:  jwt.ClaimStrings(m.Audience),
			ExpiresAt: jwt.NewNumericDate(issuedAt.Add(input.TTL)),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(notBefore),
			ID:        input.JTI,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = m.Active.KID
	signed, err := token.SignedString(m.Active.Private)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signed, nil
}

// VerifyAccessToken verifies strict EdDSA JWT claims and active/previous kid.
func (m JWTManager) VerifyAccessToken(tokenString string) (*TokenClaims, error) {
	return m.parseAccessToken(tokenString, false)
}

// VerifyExpiredAccessToken verifies everything VerifyAccessToken does except the
// expiry, returning the claims of a token whose signature is valid but whose lifetime
// has run out.
//
// This exists for RFC 7009 revocation, which is family-wide in this service: an
// expired access token is itself already useless, but it still names a token family
// whose refresh token can be live for weeks. Without a way to read the jti out of it,
// revoking an expired access token silently revokes nothing and answers 200, telling
// the client the session ended while it has not.
//
// Every other check stays in force — EdDSA only, known kid, matching issuer and
// audience, iat sanity, and the required-claim set — because the only thing safe to
// relax here is the clock. In particular this is NOT jwt.ParseUnverified: an
// unverified jti is attacker-chosen, and accepting one would let anyone revoke an
// arbitrary family. The caller must still confirm ownership against the database row
// the jti resolves to, which is what actually authorizes the revocation.
func (m JWTManager) VerifyExpiredAccessToken(tokenString string) (*TokenClaims, error) {
	return m.parseAccessToken(tokenString, true)
}

// parseAccessToken is the single parser both entry points share. The parser options
// are identical in both modes; allowExpired changes only which failure is forgiven
// afterwards, so nothing else can be relaxed by accident.
func (m JWTManager) parseAccessToken(tokenString string, allowExpired bool) (*TokenClaims, error) {
	if m.Issuer == "" || len(m.Audience) == 0 {
		return nil, ErrInvalidInput
	}
	claims := &TokenClaims{}
	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwtAlgEdDSA}),
		jwt.WithIssuer(m.Issuer),
		jwt.WithAllAudiences(m.Audience...),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithNotBeforeRequired(),
		// A small leeway so a freshly issued token is not rejected as
		// not-valid-yet by a replica whose clock lags the signer by a second or
		// two. The iat/nbf checks stay enforced; this only forgives the boundary.
		jwt.WithLeeway(5 * time.Second),
		jwt.WithTimeFunc(func() time.Time { return now(m.Clock) }),
	}
	token, err := jwt.ParseWithClaims(tokenString, claims, m.keyfunc, parserOptions...)
	if err != nil {
		// jwt/v5 joins every claim failure into one error and each stays individually
		// detectable, which is what lets expiry be forgiven on its own. Neither
		// WithoutClaimsValidation nor a back-shifted clock would do: the first disables
		// issuer and audience checking outright, and the second turns a freshly issued
		// token into "not valid yet".
		if allowExpired && isOnlyExpiredError(err) {
			if claims.ExpiresAt == nil {
				return nil, ErrInvalidToken
			}
			if validateErr := validateTokenClaims(claims); validateErr != nil {
				return nil, validateErr
			}
			return claims, nil
		}
		// Only a genuine expiry is reported as ErrExpiredToken. nbf-in-future and
		// iat-in-future are "not valid yet", not "expired": mapping them here would
		// tell callers (the revoke path, the middleware) to treat a not-yet-active
		// token as expired, which is the wrong status and, for revoke, would route it
		// into VerifyExpiredAccessToken unnecessarily. isOnlyExpiredError already
		// refuses to forgive them; this keeps the classification consistent.
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}
	if token == nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	if err := validateTokenClaims(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// isOnlyExpiredError reports whether expiry is the sole reason a token was rejected.
//
// Enumerated as a deny list of everything that must still be fatal rather than as
// "contains ErrTokenExpired", because a token can fail several validations at once: an
// expired token from a foreign issuer reports both, and treating it as merely expired
// would accept it. A signature failure never reaches here — the parser stops before
// claim validation — but it is listed anyway so the guarantee does not depend on that
// ordering.
func isOnlyExpiredError(err error) bool {
	if !errors.Is(err, jwt.ErrTokenExpired) {
		return false
	}
	// Deliberately not jwt.ErrTokenInvalidClaims: that is the wrapper every claim
	// failure is joined under, including a plain expiry, so listing it would make this
	// function always report false.
	for _, fatal := range []error{
		jwt.ErrTokenSignatureInvalid,
		jwt.ErrTokenUnverifiable,
		jwt.ErrTokenMalformed,
		jwt.ErrTokenInvalidIssuer,
		jwt.ErrTokenInvalidAudience,
		jwt.ErrTokenInvalidSubject,
		jwt.ErrTokenInvalidId,
		jwt.ErrTokenNotValidYet,
		jwt.ErrTokenUsedBeforeIssued,
		jwt.ErrTokenRequiredClaimMissing,
	} {
		if errors.Is(err, fatal) {
			return false
		}
	}
	return true
}

// JWKS returns public JWKs for active and previous Ed25519 keys. The JWK is the
// RFC 8037 OKP form: the public key is the raw 32-byte x coordinate.
func (m JWTManager) JWKS() map[string]any {
	keys := make([]map[string]string, 0, 1+len(m.Previous))
	appendKey := func(pair JWTKeyPair) {
		public := publicKey(pair)
		if pair.KID == "" || len(public) == 0 {
			return
		}
		keys = append(keys, map[string]string{
			"kty": "OKP",
			"use": "sig",
			"kid": pair.KID,
			"crv": "Ed25519",
			"alg": jwtAlgEdDSA,
			"x":   base64.RawURLEncoding.EncodeToString(public),
		})
	}
	appendKey(m.Active)
	for _, previous := range m.Previous {
		appendKey(previous)
	}
	return map[string]any{"keys": keys}
}

func validateTokenClaims(claims *TokenClaims) error {
	if strings.TrimSpace(claims.Subject) == "" || strings.TrimSpace(claims.ID) == "" || claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.NotBefore == nil {
		return ErrInvalidToken
	}
	if strings.TrimSpace(claims.Role) == "" || strings.TrimSpace(claims.State) == "" || claims.TokenVersion < 0 {
		return ErrInvalidToken
	}
	if _, err := scope.ParseClaim(claims.Scope); err != nil {
		return ErrInvalidToken
	}
	return nil
}

func (m JWTManager) keyfunc(token *jwt.Token) (any, error) {
	if token.Method.Alg() != jwtAlgEdDSA {
		return nil, ErrInvalidToken
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, ErrInvalidToken
	}
	if public := publicKeyByKID(kid, m.Active); len(public) > 0 {
		return public, nil
	}
	for _, previous := range m.Previous {
		if public := publicKeyByKID(kid, previous); len(public) > 0 {
			return public, nil
		}
	}
	return nil, ErrInvalidToken
}

func publicKeyByKID(kid string, pair JWTKeyPair) ed25519.PublicKey {
	if pair.KID != kid {
		return nil
	}
	return publicKey(pair)
}

func publicKey(pair JWTKeyPair) ed25519.PublicKey {
	if len(pair.Public) > 0 {
		return pair.Public
	}
	if len(pair.Private) > 0 {
		return pair.Private.Public().(ed25519.PublicKey)
	}
	return nil
}
