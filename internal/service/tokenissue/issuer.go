// Package tokenissue builds signed access/refresh token pairs and their
// persistence rows. It exists so the internal session flow and the OAuth token
// endpoint issue byte-identical token metadata: family linkage, scope
// normalization and expiry are security-relevant, and two independent copies of
// this logic would drift.
package tokenissue

import (
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

// ErrNotConfigured reports a missing signing dependency.
var ErrNotConfigured = errors.New("tokenissue: issuer is not configured")

// ErrInvalidInput reports missing or inconsistent issuance input.
var ErrInvalidInput = errors.New("tokenissue: invalid input")

// Pair is a signed token pair together with the rows that record it.
type Pair struct {
	AccessToken  string
	RefreshToken string
	// ScopeClaim is the canonical space-delimited scope string that was signed.
	ScopeClaim string
	FamilyID   string
	Access     *model.OAuthAccessToken
	Refresh    *model.OAuthRefreshToken
}

// Request describes one token issuance.
type Request struct {
	User   *model.User
	Client *model.OAuthClient
	// Sequence is the refresh token's position in its family; 0 for a new family.
	Sequence int
	// FamilyID continues an existing family. Empty starts a new one.
	FamilyID string
	Scopes   []string
	// AccessTTL and RefreshTTL must both be positive.
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// Issuer signs token pairs using the service's RSA and HMAC key material.
type Issuer struct {
	JWT     *auth.JWTManager
	Refresh *auth.RefreshTokenManager
	Clock   auth.Clock
	// NewJTI and NewFamilyID override the UUID generators, for tests that need
	// deterministic identifiers.
	NewJTI      func() string
	NewFamilyID func() string
}

// Issue signs an access/refresh pair and builds their persistence rows.
//
// Nothing is written here: the caller decides which transaction the rows join, so
// registration can commit the account and its first session together and the
// OAuth token endpoint can rotate under its own family lock.
func (i Issuer) Issue(request Request) (*Pair, error) {
	if i.JWT == nil || i.Refresh == nil {
		return nil, ErrNotConfigured
	}
	if request.User == nil || request.Client == nil ||
		request.AccessTTL <= 0 || request.RefreshTTL <= 0 || request.Sequence < 0 {
		return nil, ErrInvalidInput
	}
	scopes, err := scope.Normalize(request.Scopes)
	if err != nil {
		return nil, err
	}
	scopeClaim, err := scope.Claim(scopes)
	if err != nil {
		return nil, err
	}

	now := i.now()
	familyID := request.FamilyID
	if familyID == "" {
		familyID = i.newFamilyID()
	}
	jti := i.newJTI()

	// azp is derived from the client on the request rather than passed in, so no
	// call site can issue a token that fails to name its authorized party. The
	// internal middleware rejects any azp other than the built-in client, which is
	// what stops a third-party token from acting as a session credential.
	accessToken, err := i.JWT.SignAccessToken(auth.TokenInput{
		Subject:         strconv.FormatInt(request.User.ID, 10),
		JTI:             jti,
		Role:            string(request.User.Role),
		State:           string(request.User.State),
		TokenVersion:    request.User.TokenVersion,
		Scopes:          scopes,
		TTL:             request.AccessTTL,
		NotBefore:       now,
		AuthorizedParty: request.Client.ClientID,
	})
	if err != nil {
		return nil, err
	}
	refreshToken, err := i.Refresh.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	refreshHash, err := i.Refresh.HashRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	return &Pair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ScopeClaim:   scopeClaim,
		FamilyID:     familyID,
		Access: &model.OAuthAccessToken{
			TokenID:   jti,
			ClientID:  request.Client.ID,
			UserID:    request.User.ID,
			FamilyID:  &familyID,
			Scopes:    model.StringArray(scopes),
			ExpiresAt: now.Add(request.AccessTTL).UTC(),
			CreatedAt: now.UTC(),
		},
		Refresh: &model.OAuthRefreshToken{
			TokenHash: refreshHash,
			FamilyID:  familyID,
			Sequence:  request.Sequence,
			ClientID:  request.Client.ID,
			UserID:    request.User.ID,
			Scopes:    model.StringArray(scopes),
			ExpiresAt: now.Add(request.RefreshTTL).UTC(),
			CreatedAt: now.UTC(),
		},
	}, nil
}

func (i Issuer) now() time.Time {
	clock := i.Clock
	if clock == nil {
		clock = auth.SystemClock
	}
	return clock.Now().UTC()
}

func (i Issuer) newJTI() string {
	if i.NewJTI != nil {
		return i.NewJTI()
	}
	return uuid.NewString()
}

func (i Issuer) newFamilyID() string {
	if i.NewFamilyID != nil {
		return i.NewFamilyID()
	}
	return uuid.NewString()
}
