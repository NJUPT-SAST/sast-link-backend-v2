package cos

// Offline tests for the URL construction and validation halves of the adapter.
// Upload/Delete/AuditImage need a live bucket and are covered by the port
// contract + the service tests with fakes.

import (
	"testing"
)

func TestNewRejectsMissingCredentials(t *testing.T) {
	for _, cfg := range []Config{
		{Region: "ap-nanjing", Bucket: "sast-link-1250000000"},
		{Region: "ap-nanjing", Bucket: "sast-link-1250000000", AccessKey: "AK"},
		{Bucket: "sast-link-1250000000", AccessKey: "AK", SecretKey: "SK"},
	} {
		if _, err := New(cfg); err == nil {
			t.Fatalf("New(%+v) succeeded, want credential rejection", cfg)
		}
	}
}

func TestNewRejectsMalformedBucket(t *testing.T) {
	cfg := Config{Region: "ap-nanjing", Bucket: "sastlink", AccessKey: "AK", SecretKey: "SK"}
	if _, err := New(cfg); err == nil {
		t.Fatal("New with a dashless bucket succeeded, want {name}-{appid} rejection")
	}
}

func TestNewBuildsDefaultBucketURL(t *testing.T) {
	client, err := New(Config{Region: "ap-nanjing", Bucket: "sast-link-1250000000", AccessKey: "AK", SecretKey: "SK"})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if got := client.PublicURL("avatar/1/x.jpg"); got != "https://sast-link-1250000000.cos.ap-nanjing.myqcloud.com/avatar/1/x.jpg" {
		t.Fatalf("PublicURL = %q, want the default bucket host URL", got)
	}
}

func TestNewHonorsEndpointAndBaseURL(t *testing.T) {
	client, err := New(Config{
		Endpoint:  "sast-link-1250000000.cos-internal.ap-nanjing.myqcloud.com",
		Region:    "ap-nanjing",
		Bucket:    "sast-link-1250000000",
		AccessKey: "AK",
		SecretKey: "SK",
		BaseURL:   "https://cdn.sast.fun/",
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	// The base URL trims its trailing slash and prefixes every public URL.
	if got := client.PublicURL("avatar/1/x.jpg"); got != "https://cdn.sast.fun/avatar/1/x.jpg" {
		t.Fatalf("PublicURL = %q, want the base-URL form", got)
	}
	if got := client.Bucket(); got != "sast-link-1250000000" {
		t.Fatalf("Bucket() = %q", got)
	}
}
