// Package objectstore defines the storage ports the avatar upload flow depends
// on. Implementations live in internal/adapter; the session service only sees
// these interfaces, so the upload use case is testable without a real bucket.
package objectstore

import (
	"context"
	"io"
)

// ObjectStore persists objects and returns their public URL. The uploaded
// object must be publicly readable: the URL is stored in profile.avatar and
// rendered on public display cards and OIDC picture claims.
type ObjectStore interface {
	// Upload writes the reader's content under key with the given content type.
	// size is the exact byte count; a mismatch between the declared size and the
	// reader is an implementation error, not a retryable condition. The returned
	// URL is the stable public address of the object.
	Upload(ctx context.Context, key string, r io.Reader, contentType string, size int64) (string, error)
	// Delete removes the object under key. Deleting a key that does not exist is
	// not an error: the callers use Delete for best-effort cleanup (compensation
	// after a failed write, removing a superseded avatar), where a missing object
	// is the desired end state.
	Delete(ctx context.Context, key string) error
}

// AuditResult is the verdict of an image content review.
type AuditResult struct {
	// Sensitive reports whether the image hit any reviewed scene (pornography,
	// terrorism, politics, ads). A false verdict means the image is clear.
	Sensitive bool
	// Label is the review verdict label (e.g. "Normal" or the hit scene).
	Label string
}

// AvatarAuditor reviews an uploaded image for prohibited content. It is
// fail-closed by contract: an Auditor error means the image was NOT reviewed,
// and the caller must treat that as a rejected upload rather than proceeding.
type AvatarAuditor interface {
	// AuditImage reviews the object at key. It returns (result, nil) on a
	// completed review and a non-nil error when the review service was
	// unreachable or refused the request.
	AuditImage(ctx context.Context, key string) (AuditResult, error)
}
