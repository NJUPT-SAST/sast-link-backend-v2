package scope

import (
	"errors"
	"reflect"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
		valid bool
	}{
		{name: "canonical", input: []string{OpenID, Profile, Email}, want: []string{OpenID, Profile, Email}, valid: true},
		{name: "reorders", input: []string{Email, OpenID}, want: []string{OpenID, Email}, valid: true},
		{name: "openid only", input: []string{OpenID}, want: []string{OpenID}, valid: true},
		{name: "empty", input: nil},
		{name: "missing openid", input: []string{Profile}},
		{name: "unknown", input: []string{OpenID, "admin"}},
		{name: "duplicate", input: []string{OpenID, OpenID}},
		{name: "leading whitespace", input: []string{" " + OpenID}},
		{name: "embedded whitespace", input: []string{OpenID, "user profile"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Normalize(test.input)
			if test.valid {
				if err != nil {
					t.Fatalf("Normalize() error = %v", err)
				}
				if !reflect.DeepEqual(got, test.want) {
					t.Fatalf("Normalize() = %#v, want %#v", got, test.want)
				}
				return
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Normalize() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestClaimAndParseClaim(t *testing.T) {
	claim, err := Claim([]string{Email, OpenID, Profile})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if claim != "openid profile email" {
		t.Fatalf("Claim() = %q, want canonical claim", claim)
	}
	parsed, err := ParseClaim(claim)
	if err != nil {
		t.Fatalf("ParseClaim() error = %v", err)
	}
	if !reflect.DeepEqual(parsed, []string{OpenID, Profile, Email}) {
		t.Fatalf("ParseClaim() = %#v, want canonical scopes", parsed)
	}

	for _, invalid := range []string{"", " profile", "openid  profile", "openid\tprofile", "profile", "openid admin"} {
		if _, err := ParseClaim(invalid); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ParseClaim(%q) error = %v, want ErrInvalid", invalid, err)
		}
	}
}

// The admin scopes must survive the claim round trip. The colon is a legal
// RFC 6749 scope-token character, but Normalize rejects embedded whitespace and
// ParseClaim splits on single spaces, so a name containing punctuation is worth
// pinning rather than assuming.
func TestAdminScopesRoundTripThroughClaim(t *testing.T) {
	claim, err := Claim([]string{AdminWrite, OpenID, AdminRead})
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if claim != "openid admin:read admin:write" {
		t.Fatalf("Claim() = %q, want canonical admin claim", claim)
	}
	parsed, err := ParseClaim(claim)
	if err != nil {
		t.Fatalf("ParseClaim() error = %v", err)
	}
	if !reflect.DeepEqual(parsed, []string{OpenID, AdminRead, AdminWrite}) {
		t.Fatalf("ParseClaim() = %#v, want canonical admin scopes", parsed)
	}
}

// openid stays mandatory for an admin grant: the delegated token still identifies
// a subject, and every downstream path assumes openid is present.
func TestAdminScopeStillRequiresOpenID(t *testing.T) {
	if _, err := Normalize([]string{AdminWrite}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Normalize(admin:write alone) error = %v, want ErrInvalid", err)
	}
}

func TestIsAdminAndContainsAdmin(t *testing.T) {
	for _, name := range []string{AdminRead, AdminWrite} {
		if !IsAdmin(name) {
			t.Fatalf("IsAdmin(%q) = false, want true", name)
		}
	}
	for _, name := range []string{OpenID, Profile, Email, "admin", "admin:", ""} {
		if IsAdmin(name) {
			t.Fatalf("IsAdmin(%q) = true, want false", name)
		}
	}
	if ContainsAdmin([]string{OpenID, Profile, Email}) {
		t.Fatal("ContainsAdmin(session scopes) = true, want false")
	}
	if !ContainsAdmin([]string{OpenID, AdminRead}) {
		t.Fatal("ContainsAdmin(openid admin:read) = false, want true")
	}
	// Deliberately unvalidated: callers branch on intent before Normalize runs.
	if !ContainsAdmin([]string{AdminWrite}) {
		t.Fatal("ContainsAdmin(admin:write alone) = false, want true")
	}
}

// ClaimScopes is what keeps an admin grant from changing any OIDC answer.
func TestClaimScopesDropsAdminScopes(t *testing.T) {
	got := ClaimScopes([]string{OpenID, Profile, AdminRead, Email, AdminWrite})
	if !reflect.DeepEqual(got, []string{OpenID, Profile, Email}) {
		t.Fatalf("ClaimScopes() = %#v, want the OIDC scopes in order", got)
	}
	if got := ClaimScopes([]string{OpenID, AdminWrite}); !reflect.DeepEqual(got, []string{OpenID}) {
		t.Fatalf("ClaimScopes(openid admin:write) = %#v, want [openid]", got)
	}
}

// The built-in console client is validated against this exact set, so an admin
// scope leaking into it would both widen every session token and break that
// startup check.
func TestInternalSessionScopesExcludeAdminScopes(t *testing.T) {
	if ContainsAdmin(InternalSessionScopes) {
		t.Fatalf("InternalSessionScopes = %#v, want no admin scope", InternalSessionScopes)
	}
	if !reflect.DeepEqual(InternalSessionScopes, []string{OpenID, Profile, Email}) {
		t.Fatalf("InternalSessionScopes = %#v, want the three OIDC scopes", InternalSessionScopes)
	}
}

func TestEqualAndContainsAll(t *testing.T) {
	equal, err := Equal([]string{Email, OpenID}, []string{OpenID, Email})
	if err != nil || !equal {
		t.Fatalf("Equal() = %v, %v, want true", equal, err)
	}
	equal, err = Equal([]string{OpenID}, []string{OpenID, Profile})
	if err != nil || equal {
		t.Fatalf("Equal() = %v, %v, want false", equal, err)
	}
	contains, err := ContainsAll([]string{OpenID, Profile, Email}, []string{Email, OpenID})
	if err != nil || !contains {
		t.Fatalf("ContainsAll() = %v, %v, want true", contains, err)
	}
	contains, err = ContainsAll([]string{OpenID}, []string{OpenID, Email})
	if err != nil || contains {
		t.Fatalf("ContainsAll() = %v, %v, want false", contains, err)
	}
	if _, err := Equal([]string{OpenID, "unknown"}, []string{OpenID}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Equal() error = %v, want ErrInvalid", err)
	}
}
