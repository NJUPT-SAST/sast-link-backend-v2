// Package scope defines the OAuth/OIDC scopes supported by SAST Link.
package scope

import (
	"errors"
	"strings"
)

const (
	// OpenID identifies the authenticated subject and enables OIDC behavior.
	OpenID = "openid"
	// Profile permits access to profile claims.
	Profile = "profile"
	// Email permits access to email claims.
	Email = "email"
)

var (
	// ErrInvalid reports an unsupported, malformed, duplicated, or incomplete scope set.
	ErrInvalid = errors.New("scope: invalid scope set")
)

var canonicalOrder = [...]string{OpenID, Profile, Email}

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

func isSupported(value string) bool {
	return value == OpenID || value == Profile || value == Email
}
