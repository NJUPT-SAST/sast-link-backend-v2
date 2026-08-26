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
// AZP (OIDC "authorized party") names the client the token was issued to. On a
// shared-audience resource server it is what keeps a third-party token from
// authenticating on the internal surface (which would be account takeover): the
// internal middleware pins it so only the built-in client's tokens are accepted
// there. Omitted (empty) means a first-party session token — only the built-in
// client is ever issued one.
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
// Used by RFC 7009 revocation: an expired access token still names a token family
// whose refresh token can be live for weeks, so revoking it must read its jti. Every
// other check stays in force — this is NOT jwt.ParseUnverified, since an unverified,
// attacker-chosen jti would let anyone revoke an arbitrary family. The caller must
// still confirm ownership against the database row the jti resolves to.
func (m JWTManager) VerifyExpiredAccessToken(tokenString string) (*TokenClaims, error) {
	return m.parseAccessToken(tokenString, true)
}

// parseAccessToken is the single parser both entry points share; allowExpired
// changes only which failure is forgiven afterwards.
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
		// Small leeway so a replica whose clock lags the signer does not reject a
		// freshly issued token; the iat/nbf checks stay enforced.
		jwt.WithLeeway(5 * time.Second),
		jwt.WithTimeFunc(func() time.Time { return now(m.Clock) }),
	}
	token, err := jwt.ParseWithClaims(tokenString, claims, m.keyfunc, parserOptions...)
	if err != nil {
		// jwt/v5 joins every claim failure into one error and keeps each
		// individually detectable, so expiry can be forgiven on its own.
		if allowExpired && isOnlyExpiredError(err) {
			if claims.ExpiresAt == nil {
				return nil, ErrInvalidToken
			}
			if validateErr := validateTokenClaims(claims); validateErr != nil {
				return nil, validateErr
			}
			return claims, nil
		}
		// Only a genuine expiry is reported as ErrExpiredToken; nbf-in-future and
		// iat-in-future are "not valid yet", which isOnlyExpiredError refuses to forgive.
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
// "contains ErrTokenExpired", so an expired token from a foreign issuer is not
// treated as merely expired and accepted.
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
