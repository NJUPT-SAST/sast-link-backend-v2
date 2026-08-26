package adminclient

import (
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

const (
	maxClientNameLength  = 100
	maxRedirectURIs      = 10
	maxRedirectURILength = 2048

	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
)

// supportedGrantTypes is the closed set this provider implements; registering an
// unimplemented grant advertises a capability that fails at redemption.
var supportedGrantTypes = []string{grantAuthorizationCode, grantRefreshToken}

// validateClientName normalizes and bounds a display name.
func validateClientName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", newError(ErrInvalidInput, "client_name 不能为空", nil)
	}
	// Counted in runes, so a 100-character Chinese name is 100 characters.
	if len([]rune(trimmed)) > maxClientNameLength {
		return "", newError(ErrInvalidInput, "client_name 长度超出限制", nil)
	}
	// Control characters would corrupt the consent page.
	if strings.ContainsFunc(trimmed, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", newError(ErrInvalidInput, "client_name 含非法字符", nil)
	}
	return trimmed, nil
}

// validateRedirectURIs checks every registered callback. This is the first of the
// two open-redirect defenses: whatever is accepted here is where an authorization
// code can be delivered, and registration is the only place a human sees the
// rejection.
func validateRedirectURIs(uris []string) (model.StringArray, error) {
	if len(uris) == 0 {
		return nil, newError(ErrInvalidInput, "redirect_uris 不能为空", nil)
	}
	if len(uris) > maxRedirectURIs {
		return nil, newError(ErrInvalidInput, "redirect_uris 数量超出限制", nil)
	}
	validated := make(model.StringArray, 0, len(uris))
	for _, raw := range uris {
		uri, err := validateRedirectURI(raw)
		if err != nil {
			return nil, err
		}
		// Duplicates are rejected rather than silently deduplicated.
		if slices.Contains(validated, uri) {
			return nil, newError(ErrInvalidInput, "redirect_uris 含重复项", nil)
		}
		validated = append(validated, uri)
	}
	return validated, nil
}

func validateRedirectURI(raw string) (string, error) {
	// Not trimmed: exact matching at /oauth/authorize compares bytes, so a stored URI
	// with stray whitespace could never match and would silently never work.
	if raw == "" || raw != strings.TrimSpace(raw) {
		return "", newError(ErrInvalidInput, "redirect_uri 格式非法", nil)
	}
	if len(raw) > maxRedirectURILength {
		return "", newError(ErrInvalidInput, "redirect_uri 长度超出限制", nil)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", newError(ErrInvalidInput, "redirect_uri 格式非法", err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return "", newError(ErrInvalidInput, "redirect_uri 必须是绝对 URI", nil)
	}
	// RFC 6749 §3.1.2 forbids a fragment; the browser never sends one, so two
	// registrations could otherwise differ only in a part the server cannot see.
	if parsed.Fragment != "" || strings.Contains(raw, "#") {
		return "", newError(ErrInvalidInput, "redirect_uri 不得包含 fragment", nil)
	}
	if parsed.User != nil {
		return "", newError(ErrInvalidInput, "redirect_uri 不得包含 userinfo", nil)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return raw, nil
	case "http":
		// Plaintext is allowed only on loopback, where there is no network to intercept
		// (RFC 8252 §7.3).
		if !isLoopbackHost(parsed.Hostname()) {
			return "", newError(ErrInvalidInput, "redirect_uri 仅允许 https，http 限 localhost", nil)
		}
		return raw, nil
	default:
		// Everything else — javascript:, data:, custom schemes — is refused.
		return "", newError(ErrInvalidInput, "redirect_uri 仅允许 https，http 限 localhost", nil)
	}
}

func isLoopbackHost(hostname string) bool {
	// Case-insensitive because DNS is; folded as ASCII, not with strings.EqualFold,
	// whose Unicode folding accepts "localhoſt" (U+017F) as "localhost" — a distinct
	// name url.Parse preserves verbatim. net.ParseIP handles the numeric forms.
	if asciiLower(hostname) == "localhost" {
		return true
	}
	address := net.ParseIP(hostname)
	return address != nil && address.IsLoopback()
}

// asciiLower lowercases only A-Z. A host comparison wants byte equality after ASCII
// case folding, which is also what DNS itself specifies (RFC 4343); strings.ToLower
// would fold hosts that merely map to "localhost" under Unicode case rules.
func asciiLower(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, value)
}

// validateGrantTypes confines grants to what the token endpoint implements.
func validateGrantTypes(grants []string) (model.StringArray, error) {
	if len(grants) == 0 {
		return nil, newError(ErrInvalidInput, "grant_types 不能为空", nil)
	}
	validated := make(model.StringArray, 0, len(grants))
	for _, grant := range grants {
		if !slices.Contains(supportedGrantTypes, grant) {
			return nil, newError(ErrInvalidInput, "grant_types 含不支持的值", nil)
		}
		if slices.Contains(validated, grant) {
			return nil, newError(ErrInvalidInput, "grant_types 含重复项", nil)
		}
		validated = append(validated, grant)
	}
	// authorization_code is the only way to obtain a token here, so a registration
	// without it could never complete a flow.
	if !slices.Contains(validated, grantAuthorizationCode) {
		return nil, newError(ErrInvalidInput, "grant_types 必须包含 authorization_code", nil)
	}
	// Canonical order, so equivalent registrations store the same array.
	return model.StringArray(slices.DeleteFunc(slices.Clone(supportedGrantTypes), func(grant string) bool {
		return !slices.Contains(validated, grant)
	})), nil
}

// validateClientType confines the type to the enum the column accepts.
func validateClientType(clientType string) (model.ClientType, error) {
	switch model.ClientType(clientType) {
	case model.ClientTypeFirstParty:
		return model.ClientTypeFirstParty, nil
	case model.ClientTypeThirdParty:
		return model.ClientTypeThirdParty, nil
	default:
		return "", newError(ErrInvalidInput, "client_type 必须为 first_party 或 third_party", nil)
	}
}
