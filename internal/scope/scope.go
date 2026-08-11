// Package scope defines the OAuth/OIDC scopes supported by SAST Link.
package scope

import (
	"errors"
	"slices"
	"strings"
)

const (
	// OpenID identifies the authenticated subject and enables OIDC behavior.
	OpenID = "openid"
	// Profile permits access to profile claims.
	Profile = "profile"
	// Email permits access to email claims.
	Email = "email"
	// AdminRead permits reading the administrative console endpoints on behalf of
	// an administrator. It grants no OIDC claim.
	AdminRead = "admin:read"
	// AdminWrite permits mutating through the administrative console endpoints on
	// behalf of an administrator. It grants no OIDC claim.
	AdminWrite = "admin:write"
)

// oidcScopes are the scopes that map to ID Token / UserInfo claims. adminScopes
// are the delegated-administration scopes, which map to no claim at all and only
// gate the /admin routes.
//
// The split matters because Normalize is the single "is this set well-formed"
// predicate for every path — JWT verification, client registration, UserInfo and
// ID Token issuance alike. Keeping the two families named separately is what lets
// the claim-emitting paths filter deliberately (see ClaimScopes) instead of
// relying on their switch statements happening to ignore a name they don't know.
var (
	oidcScopes  = []string{OpenID, Profile, Email}
	adminScopes = []string{AdminRead, AdminWrite}
)

// InternalSessionScopes is the canonical scope set issued by the internal
// authentication session (login/refresh). It is the single source of truth
// shared by cmd/api startup validation and the session service.
//
// Deliberately the OIDC scopes alone: the built-in console client is validated
// against this exact set, and a session token must never carry an admin scope —
// delegated administration is a separate client's grant, not something every
// login receives.
var InternalSessionScopes = slices.Clone(oidcScopes)

var (
	// ErrInvalid reports an unsupported, malformed, duplicated, or incomplete scope set.
	ErrInvalid = errors.New("scope: invalid scope set")
)

var canonicalOrder = [...]string{OpenID, Profile, Email, AdminRead, AdminWrite}

// Normalize validates scopes and returns them in the canonical protocol order.
// OAuth requests for this service must always include openid.
func Normalize(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, ErrInvalid
	}

	requested := make(map[string]struct{}, len(scopes))
	for _, item := range scopes {
		if item == "" || strings.TrimSpace(item) != item || strings.ContainsAny(item, " \t\r\n") {
			return nil, ErrInvalid
		}
		if !isSupported(item) {
			return nil, ErrInvalid
		}
		if _, exists := requested[item]; exists {
			return nil, ErrInvalid
		}
		requested[item] = struct{}{}
	}
	if _, exists := requested[OpenID]; !exists {
		return nil, ErrInvalid
	}

	normalized := make([]string, 0, len(requested))
	for _, item := range canonicalOrder {
		if _, exists := requested[item]; exists {
			normalized = append(normalized, item)
		}
	}
	return normalized, nil
}

// Claim validates scopes and encodes them as the OAuth single-valued scope claim.
func Claim(scopes []string) (string, error) {
	normalized, err := Normalize(scopes)
	if err != nil {
		return "", err
	}
	return strings.Join(normalized, " "), nil
}

// ParseClaim strictly parses an OAuth space-delimited scope claim.
func ParseClaim(value string) ([]string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\t\r\n") {
		return nil, ErrInvalid
	}
	parts := strings.Split(value, " ")
	for _, part := range parts {
		if part == "" {
			return nil, ErrInvalid
		}
	}
	return Normalize(parts)
}

// Equal reports whether two scope sets are valid and contain the same scopes.
func Equal(left, right []string) (bool, error) {
	leftNormalized, err := Normalize(left)
	if err != nil {
		return false, err
	}
	rightNormalized, err := Normalize(right)
	if err != nil {
		return false, err
	}
	if len(leftNormalized) != len(rightNormalized) {
		return false, nil
	}
	for index := range leftNormalized {
		if leftNormalized[index] != rightNormalized[index] {
			return false, nil
		}
	}
	return true, nil
}

// ContainsAll reports whether granted contains every requested scope.
func ContainsAll(granted, requested []string) (bool, error) {
	grantedNormalized, err := Normalize(granted)
	if err != nil {
		return false, err
	}
	requestedNormalized, err := Normalize(requested)
	if err != nil {
		return false, err
	}
	grantedSet := make(map[string]struct{}, len(grantedNormalized))
	for _, item := range grantedNormalized {
		grantedSet[item] = struct{}{}
	}
	for _, item := range requestedNormalized {
		if _, exists := grantedSet[item]; !exists {
			return false, nil
		}
	}
	return true, nil
}

// IsAdmin reports whether one scope name is a delegated-administration scope.
func IsAdmin(value string) bool {
	return slices.Contains(adminScopes, value)
}

// ContainsAdmin reports whether a scope set carries any admin scope. It does not
// validate the set: callers use it to branch on intent (an authorize request
// asking for administration, a token presented to /admin) before or independently
// of Normalize.
func ContainsAdmin(scopes []string) bool {
	return slices.ContainsFunc(scopes, IsAdmin)
}

// ClaimScopes drops the admin scopes, keeping the remainder in its original
// order. It is what the ID Token signer and UserInfo apply before mapping scopes
// to claims.
//
// An admin scope grants no claim, so filtering here rather than rejecting is the
// correct behavior: a token holding "openid admin:read" was legitimately issued,
// and refusing to answer UserInfo for it would break OIDC for a valid token. It
// simply receives sub alone.
func ClaimScopes(granted []string) []string {
	filtered := make([]string, 0, len(granted))
	for _, item := range granted {
		if !IsAdmin(item) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func isSupported(value string) bool {
	return slices.Contains(oidcScopes, value) || slices.Contains(adminScopes, value)
}
