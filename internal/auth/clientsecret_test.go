package auth

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestNewClientSecretRoundTrips(t *testing.T) {
	hasher := ClientSecretHasher{Random: fixedReader{data: bytes.Repeat([]byte{0x7f}, 32)}}
	secret, encodedHash, err := hasher.NewClientSecret()
	if err != nil {
		t.Fatalf("NewClientSecret returned error: %v", err)
	}
	if !strings.HasPrefix(encodedHash, "sha256-v1$") {
		t.Fatalf("hash = %q, want versioned sha256 format", encodedHash)
	}
	// oauth_clients.client_secret is VARCHAR(255); a hash that overflows it would
	// fail at insert time rather than here.
	if len(encodedHash) > 255 {
		t.Fatalf("hash length = %d, want at most the column width of 255", len(encodedHash))
	}
	if err := VerifyClientSecret(secret, encodedHash); err != nil {
		t.Fatalf("VerifyClientSecret returned error: %v", err)
	}
	if err := VerifyClientSecret(secret+"x", encodedHash); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("VerifyClientSecret wrong secret error = %v, want ErrInvalidSecret", err)
	}
}

// The plaintext must never be recoverable from what is stored, and two calls must
// not collide: a shared secret across clients would let one impersonate another.
func TestNewClientSecretIsHighEntropyAndUnique(t *testing.T) {
	hasher := ClientSecretHasher{}
	first, firstHash, err := hasher.NewClientSecret()
	if err != nil {
		t.Fatalf("NewClientSecret returned error: %v", err)
	}
	second, secondHash, err := hasher.NewClientSecret()
	if err != nil {
		t.Fatalf("NewClientSecret returned error: %v", err)
	}
	if first == second || firstHash == secondHash {
		t.Fatal("two generated client secrets collided")
	}
	if strings.Contains(firstHash, first) {
		t.Fatal("stored hash contains the plaintext secret")
	}
	if err := VerifyClientSecret(second, firstHash); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("cross-verification error = %v, want ErrInvalidSecret", err)
	}
}

// An empty presented secret must fail before hashing. A client that sends no
// client_secret would otherwise be compared against the hash of the empty
// string, which a misconfigured row could hold, and would authenticate.
func TestVerifyClientSecretRejectsEmptyAndMalformed(t *testing.T) {
	validHash := HashClientSecret("a-secret")

	tests := []struct {
		name    string
		secret  string
		hash    string
		wantErr error
	}{
		{name: "empty secret", secret: "", hash: validHash, wantErr: ErrInvalidInput},
		{name: "empty secret against hash of empty", secret: "", hash: HashClientSecret(""), wantErr: ErrInvalidInput},
		{name: "no version separator", secret: "a-secret", hash: "deadbeef", wantErr: ErrInvalidInput},
		{name: "unknown version", secret: "a-secret", hash: "sha512-v9$deadbeef", wantErr: ErrUnsupportedVersion},
		{name: "hash not base64", secret: "a-secret", hash: "sha256-v1$not!base64", wantErr: ErrInvalidInput},
		{name: "hash wrong length", secret: "a-secret", hash: "sha256-v1$AAAA", wantErr: ErrInvalidInput},
		{name: "empty hash", secret: "a-secret", hash: "", wantErr: ErrInvalidInput},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifyClientSecret(test.secret, test.hash); !errors.Is(err, test.wantErr) {
				t.Fatalf("VerifyClientSecret error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

// A golden value, not a self-comparison: the hash is persisted, so a change to
// the encoding would silently invalidate every registered client's secret. This
// pins the format so such a change has to be deliberate.
func TestHashClientSecretMatchesGoldenValue(t *testing.T) {
	// sha256("a-secret"), base64url without padding.
	const want = "sha256-v1$tNh1JDk7Red5PiPxkuaoWhC65vsmeemWp6y4ymC0yI0"
	if got := HashClientSecret("a-secret"); got != want {
		t.Fatalf("HashClientSecret = %q, want %q", got, want)
	}
	if HashClientSecret("a") == HashClientSecret("b") {
		t.Fatal("HashClientSecret collided on distinct inputs")
	}
}
