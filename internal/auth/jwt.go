package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

const jwtAlgRS256 = "RS256"

// JWTKeyPair is an RSA key pair identified by kid.
type JWTKeyPair struct {
	KID     string
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

// TokenClaims are access-token claims used by SAST Link.
type TokenClaims struct {
	Role         string `json:"role"`
	State        string `json:"state"`
	TokenVersion int    `json:"token_version"`
	Scope        string `json:"scope"`
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
}

// JWTManager signs with the active key and verifies with active plus previous keys.
type JWTManager struct {
	Issuer   string
	Audience []string
	Active   JWTKeyPair
	Previous []JWTKeyPair
	Clock    Clock
}

// SignAccessToken signs an RS256 JWT with the active private key and kid.
func (m JWTManager) SignAccessToken(input TokenInput) (string, error) {
	scopeClaim, err := scope.Claim(input.Scopes)
	if err != nil {
		return "", ErrInvalidInput
	}
	if m.Issuer == "" || input.Subject == "" || input.JTI == "" || strings.TrimSpace(input.Role) == "" || strings.TrimSpace(input.State) == "" ||
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
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.Active.KID
	signed, err := token.SignedString(m.Active.Private)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signed, nil
}

// VerifyAccessToken verifies strict RS256 JWT claims and active/previous kid.
func (m JWTManager) VerifyAccessToken(tokenString string) (*TokenClaims, error) {
	if m.Issuer == "" || len(m.Audience) == 0 {
		return nil, ErrInvalidInput
	}
	claims := &TokenClaims{}
	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwtAlgRS256}),
		jwt.WithIssuer(m.Issuer),
		jwt.WithAllAudiences(m.Audience...),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithNotBeforeRequired(),
		jwt.WithTimeFunc(func() time.Time { return now(m.Clock) }),
	}
	token, err := jwt.ParseWithClaims(tokenString, claims, m.keyfunc, parserOptions...)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) || errors.Is(err, jwt.ErrTokenUsedBeforeIssued) {
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

// JWKS returns public JWKs for active and previous RSA keys.
func (m JWTManager) JWKS() map[string]any {
	keys := make([]map[string]string, 0, 1+len(m.Previous))
	appendKey := func(pair JWTKeyPair) {
		public := publicKey(pair)
		if pair.KID == "" || public == nil {
			return
		}
		keys = append(keys, map[string]string{
			"kty": "RSA",
			"use": "sig",
			"kid": pair.KID,
			"alg": jwtAlgRS256,
			"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
		})
	}
	appendKey(m.Active)
	for _, previous := range m.Previous {
		appendKey(previous)
	}
	return map[string]any{"keys": keys}
}

func validateTokenClaims(claims *TokenClaims) error {
	if claims.Subject == "" || claims.ID == "" || claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.NotBefore == nil {
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
	if token.Method.Alg() != jwtAlgRS256 {
		return nil, ErrInvalidToken
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, ErrInvalidToken
	}
	if public := publicKeyByKID(kid, m.Active); public != nil {
		return public, nil
	}
	for _, previous := range m.Previous {
		if public := publicKeyByKID(kid, previous); public != nil {
			return public, nil
		}
	}
	return nil, ErrInvalidToken
}

func publicKeyByKID(kid string, pair JWTKeyPair) *rsa.PublicKey {
	if pair.KID != kid {
		return nil
	}
	return publicKey(pair)
}

func publicKey(pair JWTKeyPair) *rsa.PublicKey {
	if pair.Public != nil {
		return pair.Public
	}
	if pair.Private != nil {
		return &pair.Private.PublicKey
	}
	return nil
}
