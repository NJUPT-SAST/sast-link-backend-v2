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
