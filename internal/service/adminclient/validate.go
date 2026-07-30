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

// supportedGrantTypes is the closed set this provider implements. Registering a
// grant the token endpoint does not implement would advertise a capability that
// fails at redemption.
var supportedGrantTypes = []string{grantAuthorizationCode, grantRefreshToken}

// validateClientName normalizes and bounds a display name.
func validateClientName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", newError(ErrInvalidInput, "client_name 不能为空", nil)
	}
	// Counted in runes: a 100-character Chinese name is not 300 characters long.
	if len([]rune(trimmed)) > maxClientNameLength {
		return "", newError(ErrInvalidInput, "client_name 长度超出限制", nil)
	}
	// Control characters would corrupt the consent page that displays this name.
	if strings.ContainsFunc(trimmed, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", newError(ErrInvalidInput, "client_name 含非法字符", nil)
	}
	return trimmed, nil
}

// validateRedirectURIs checks every registered callback.
//
// This is the first of the two open-redirect defenses. /oauth/authorize matches the
// incoming redirect_uri against this list by exact string equality, so whatever is
// accepted here is what an authorization code can be delivered to — a registration
// holding "javascript:..." or an open redirector on the client's domain would make
// exact matching worthless. Validating at registration is also the only place a
// human is present to see the rejection.
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
		// Duplicates are rejected rather than deduplicated: a repeated entry means the
		// submitter did not mean what they wrote, and silently changing their list is
		// worse than telling them.
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
	// RFC 6749 §3.1.2: the endpoint URI must not include a fragment. The browser
	// never sends a fragment to the server, so one here cannot be matched and would
	// also let two registrations differ only in a part the server cannot see.
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
		// Plaintext is allowed only on loopback, where there is no network to intercept.
		// This is what lets a developer run the client locally; RFC 8252 §7.3 takes the
		// same position for native apps.
		if !isLoopbackHost(parsed.Hostname()) {
			return "", newError(ErrInvalidInput, "redirect_uri 仅允许 https，http 限 localhost", nil)
		}
		return raw, nil
	default:
		// Everything else — javascript:, data:, custom schemes — is refused. A custom
		// scheme would need its own review; the two above are what this provider serves.
		return "", newError(ErrInvalidInput, "redirect_uri 仅允许 https，http 限 localhost", nil)
	}
}

func isLoopbackHost(hostname string) bool {
	// Case-insensitive because DNS is: "LOCALHOST" names the same host, and rejecting
	// it would be a false refusal of a valid loopback registration.
	//
	// Folded as ASCII rather than with strings.EqualFold, which applies Unicode simple
	// folding: U+017F (ſ, long s) folds to "s", so EqualFold accepts "localhoſt" — a
	// distinct name url.Parse preserves verbatim, which would register a plaintext http
	// URI for a host this provider never vetted. Only the ASCII spelling names loopback;
	// net.ParseIP handles the numeric forms, and 127.0.0.1.evil.com and 0.0.0.0 still fail.
	if asciiLower(hostname) == "localhost" {
		return true
	}
	address := net.ParseIP(hostname)
	return address != nil && address.IsLoopback()
}

// asciiLower lowercases only A-Z, leaving every other byte untouched.
//
// Deliberately not strings.ToLower, which is Unicode-aware: folding a hostname with
// case mappings outside ASCII would let a name that merely folds to "localhost"
// answer to it. A host comparison wants byte equality after ASCII case folding, which
// is also what DNS itself specifies (RFC 4343).
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
	// Canonical order, so two registrations listing the same grants store the same
	// array and comparisons in tests and logs stay stable.
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
