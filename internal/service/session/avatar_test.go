package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/objectstore"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// fakeAvatarStore records uploads and deletes like a real bucket.
type fakeAvatarStore struct {
	baseURL   string
	uploads   map[string][]byte
	deleted   []string
	uploadErr error
	deleteErr error
}

func newFakeAvatarStore(baseURL string) *fakeAvatarStore {
	return &fakeAvatarStore{baseURL: baseURL, uploads: map[string][]byte{}}
}

func (f *fakeAvatarStore) Upload(_ context.Context, key string, r io.Reader, _ string, _ int64) (string, error) {
	if f.uploadErr != nil {
		return "", f.uploadErr
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	f.uploads[key] = data
	return f.baseURL + "/" + key, nil
}

func (f *fakeAvatarStore) Delete(_ context.Context, key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, key)
	delete(f.uploads, key)
	return nil
}

// fakeAvatarAuditor returns a fixed verdict or error.
type fakeAvatarAuditor struct {
	result objectstore.AuditResult
	err    error
	calls  []string
}

func (f *fakeAvatarAuditor) AuditImage(_ context.Context, key string) (objectstore.AuditResult, error) {
	f.calls = append(f.calls, key)
	if f.err != nil {
		return objectstore.AuditResult{}, f.err
	}
	return f.result, nil
}

// avatarService builds a session Service with avatar fakes wired in.
func avatarService(t *testing.T) (Service, *fakeUsers, *fakeAvatarStore, *fakeAvatarAuditor, *fakeAudit) {
	t.Helper()
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	store := newFakeAvatarStore("https://cdn.example.com")
	auditor := &fakeAvatarAuditor{result: objectstore.AuditResult{Sensitive: false, Label: "Normal"}}
	service.AvatarStore = store
	service.AvatarAuditor = auditor
	service.AvatarLimiter = &fakeLimiter{}
	return service, users, store, auditor, service.Audit.(*fakeAudit)
}

// testImageBytes returns valid encoded bytes for one of the accepted formats.
func testImageBytes(t *testing.T, format string) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	var buf bytes.Buffer
	switch format {
	case "jpeg":
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
			t.Fatalf("encode test jpeg: %v", err)
		}
	case "png":
		if err := png.Encode(&buf, img); err != nil {
			t.Fatalf("encode test png: %v", err)
		}
	case "webp":
		// Minimal but valid VP8L file: RIFF/WEBP container, 1x1 lossless image.
		// DecodeConfig only reads the 5-byte VP8L header, so no pixel data is
		// needed for the config-only path this service exercises.
		payload := []byte{0x2F, 0x00, 0x00, 0x00, 0x00}
		chunk := append([]byte("VP8L"), u32le(uint32(len(payload)))...) //nolint:gosec // payload is a 5-byte constant
		chunk = append(chunk, payload...)
		file := append([]byte("RIFF"), u32le(uint32(len(chunk)+4))...) //nolint:gosec // chunk is a 13-byte constant
		file = append(file, []byte("WEBP")...)
		file = append(file, chunk...)
		return file
	default:
		t.Fatalf("unknown test format %q", format)
	}
	return buf.Bytes()
}

func u32le(value uint32) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, value)
	return out
}

func TestUploadAvatarStoresObjectAndUpdatesProfile(t *testing.T) {
	service, users, store, auditor, audit := avatarService(t)
	imageData := testImageBytes(t, "png")

	result, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
	})
	if err != nil {
		t.Fatalf("UploadAvatar returned error: %v", err)
	}
	if !strings.HasPrefix(result.AvatarURL, "https://cdn.example.com/avatar/42/") ||
		!strings.HasSuffix(result.AvatarURL, ".png") {
		t.Fatalf("avatar URL = %q, want https://cdn.example.com/avatar/42/<uuid>.png", result.AvatarURL)
	}
	key := strings.TrimPrefix(result.AvatarURL, "https://cdn.example.com/")
	if _, ok := store.uploads[key]; !ok {
		t.Fatalf("uploaded key %q not found in store: %+v", key, store.uploads)
	}
	if got := users.byID[42].Profile.Avatar; got == nil || *got != result.AvatarURL {
		t.Fatalf("profile.avatar = %v, want %q", got, result.AvatarURL)
	}
	if len(auditor.calls) != 1 || auditor.calls[0] != key {
		t.Fatalf("audited keys = %v, want [%s]", auditor.calls, key)
	}
	entry := audit.entries[len(audit.entries)-1]
	if entry.Action != "upload_avatar" || entry.Success == nil || !*entry.Success || entry.UserID == nil || *entry.UserID != 42 {
		t.Fatalf("audit entry = %+v, want upload_avatar success for user 42", entry)
	}
	if string(entry.Detail) == "" || !strings.Contains(string(entry.Detail), result.AvatarURL) {
		t.Fatalf("audit detail = %s, want avatar_url present", entry.Detail)
	}
}

func TestUploadAvatarAcceptsAllDocumentedFormats(t *testing.T) {
	for _, format := range []string{"jpeg", "png", "webp"} {
		service, _, store, _, _ := avatarService(t)
		imageData := testImageBytes(t, format)
		if _, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
			UserID: 42, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
		}); err != nil {
			t.Fatalf("format %s rejected: %v", format, err)
		}
		if len(store.uploads) != 1 {
			t.Fatalf("format %s: uploads = %d, want 1", format, len(store.uploads))
		}
	}
}

func TestUploadAvatarRejectsUnsupportedFormat(t *testing.T) {
	service, _, store, _, _ := avatarService(t)
	content := []byte("GIF89a this is not an accepted format at all")
	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(content), Size: int64(len(content)),
	})
	if !isKind(err, KindInvalidInput) {
		t.Fatalf("error = %v, want invalid input", err)
	}
	if len(store.uploads) != 0 {
		t.Fatalf("store has %d uploads, want 0", len(store.uploads))
	}
}

// A spoofed filename or declared content type must not bypass the magic-byte
// check: the bytes are what gets stored and rendered.
func TestUploadAvatarRejectsSpoofedFilename(t *testing.T) {
	service, _, store, _, _ := avatarService(t)
	content := []byte("plain text pretending to be an image")
	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Filename: "photo.jpg", Content: bytes.NewReader(content), Size: int64(len(content)),
	})
	if !isKind(err, KindInvalidInput) {
		t.Fatalf("error = %v, want invalid input", err)
	}
	if len(store.uploads) != 0 {
		t.Fatalf("store has %d uploads, want 0", len(store.uploads))
	}
}

// A declared size over the cap is rejected without reading the body.
func TestUploadAvatarRejectsDeclaredSizeOverCap(t *testing.T) {
	service, _, store, _, _ := avatarService(t)
	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(testImageBytes(t, "png")), Size: maxAvatarSize + 1,
	})
	if !isKind(err, KindInvalidInput) {
		t.Fatalf("error = %v, want invalid input", err)
	}
	if len(store.uploads) != 0 {
		t.Fatalf("store has %d uploads, want 0", len(store.uploads))
	}
}

// A lying declared size must not let an oversized body through: the limit is
// enforced on the actual stream.
func TestUploadAvatarRejectsActualSizeOverCap(t *testing.T) {
	service, _, store, _, _ := avatarService(t)
	// A reader that reports no size and yields more than the cap.
	big := bytes.Repeat([]byte{0x00}, maxAvatarSize+1024)
	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(big), Size: 0,
	})
	if !isKind(err, KindInvalidInput) {
		t.Fatalf("error = %v, want invalid input", err)
	}
	if len(store.uploads) != 0 {
		t.Fatalf("store has %d uploads, want 0", len(store.uploads))
	}
}

// JPEG magic bytes with garbage payload must be rejected by the decode check,
// not stored.
func TestUploadAvatarRejectsCorruptImage(t *testing.T) {
	service, _, store, _, _ := avatarService(t)
	content := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, bytes.Repeat([]byte{0xAB}, 64)...)
	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(content), Size: int64(len(content)),
	})
	if !isKind(err, KindInvalidInput) {
		t.Fatalf("error = %v, want invalid input", err)
	}
	if len(store.uploads) != 0 {
		t.Fatalf("store has %d uploads, want 0", len(store.uploads))
	}
}

func TestUploadAvatarRejectsEmptyContent(t *testing.T) {
	service, _, store, _, _ := avatarService(t)
	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(nil), Size: 0,
	})
	if !isKind(err, KindInvalidInput) {
		t.Fatalf("error = %v, want invalid input", err)
	}
	if len(store.uploads) != 0 {
		t.Fatalf("store has %d uploads, want 0", len(store.uploads))
	}
}

// A sensitive verdict must reject the upload, remove the stored object and
// leave profile.avatar untouched.
func TestUploadAvatarRejectsSensitiveContent(t *testing.T) {
	service, users, store, auditor, audit := avatarService(t)
	auditor.result = objectstore.AuditResult{Sensitive: true, Label: "Porn"}
	imageData := testImageBytes(t, "png")

	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
	})
	var serviceErr *Error
	if !errors.As(err, &serviceErr) || serviceErr.Code != errcode.CodeValidationFailed {
		t.Fatalf("error = %v, want validation-failed code", err)
	}
	if len(store.uploads) != 0 {
		t.Fatalf("store still has %d objects, want 0 after rejection", len(store.uploads))
	}
	if got := users.byID[42].Profile.Avatar; got != nil {
		t.Fatalf("profile.avatar = %v, want nil after rejection", *got)
	}
	entry := audit.entries[len(audit.entries)-1]
	if entry.Action != "upload_avatar" || entry.Success == nil || *entry.Success || entry.ErrCode == nil || *entry.ErrCode != errcode.CodeValidationFailed {
		t.Fatalf("audit entry = %+v, want failed upload_avatar with 42200", entry)
	}
	if !strings.Contains(string(entry.Detail), "Porn") {
		t.Fatalf("audit detail = %s, want rejected label", entry.Detail)
	}
}

// An unreachable review service is fail-closed: the upload fails and the object
// is removed rather than served unvetted.
func TestUploadAvatarFailClosedWhenAuditUnavailable(t *testing.T) {
	service, _, store, auditor, _ := avatarService(t)
	auditor.err = errors.New("review service down")
	imageData := testImageBytes(t, "png")

	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
	})
	var serviceErr *Error
	if !errors.As(err, &serviceErr) || serviceErr.Code != errcode.CodeObjectUploadFailed {
		t.Fatalf("error = %v, want object-upload-failed code", err)
	}
	if len(store.uploads) != 0 {
		t.Fatalf("store still has %d objects, want 0 after fail-closed rejection", len(store.uploads))
	}
}

// Audit disabled (nil auditor) means no review step at all.
func TestUploadAvatarSkipsAuditWhenDisabled(t *testing.T) {
	service, _, store, auditor, _ := avatarService(t)
	service.AvatarAuditor = nil
	imageData := testImageBytes(t, "png")

	if _, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
	}); err != nil {
		t.Fatalf("UploadAvatar returned error: %v", err)
	}
	if len(auditor.calls) != 0 {
		t.Fatalf("auditor called %d times, want 0", len(auditor.calls))
	}
	if len(store.uploads) != 1 {
		t.Fatalf("uploads = %d, want 1", len(store.uploads))
	}
}

func TestUploadAvatarFailsWhenStoreUnavailable(t *testing.T) {
	service, _, store, _, _ := avatarService(t)
	store.uploadErr = errors.New("bucket unreachable")
	imageData := testImageBytes(t, "png")

	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
	})
	var serviceErr *Error
	if !errors.As(err, &serviceErr) || serviceErr.Code != errcode.CodeObjectUploadFailed {
		t.Fatalf("error = %v, want object-upload-failed code", err)
	}
}

// Without storage configured the endpoint reports the documented 50002 instead
// of failing at boot.
func TestUploadAvatarFailsWithoutStore(t *testing.T) {
	service, _, _, _, _ := avatarService(t)
	service.AvatarStore = nil
	imageData := testImageBytes(t, "png")

	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
	})
	var serviceErr *Error
	if !errors.As(err, &serviceErr) || serviceErr.Code != errcode.CodeObjectUploadFailed {
		t.Fatalf("error = %v, want object-upload-failed code", err)
	}
}

// A failed profile write must compensate by removing the freshly uploaded
// object, so no orphan accumulates in storage.
func TestUploadAvatarCompensatesOnDatabaseError(t *testing.T) {
	service, users, store, _, _ := avatarService(t)
	users.updateProfileErr = errors.New("db down")
	imageData := testImageBytes(t, "png")

	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
	})
	var serviceErr *Error
	if !errors.As(err, &serviceErr) || serviceErr.Code != errcode.CodeDatabaseFailed {
		t.Fatalf("error = %v, want database-failed code", err)
	}
	if len(store.uploads) != 0 {
		t.Fatalf("store still has %d objects, want 0 after compensation", len(store.uploads))
	}
}

func TestUploadAvatarRateLimited(t *testing.T) {
	service, _, store, _, _ := avatarService(t)
	service.AvatarLimiter = &fakeLimiter{result: LimitResult{Allowed: false, RetryAfter: time.Second}}
	imageData := testImageBytes(t, "png")

	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
	})
	if !isKind(err, KindRateLimited) {
		t.Fatalf("error = %v, want rate limited", err)
	}
	if len(store.uploads) != 0 {
		t.Fatalf("store has %d uploads, want 0 (throttled before upload)", len(store.uploads))
	}
}

// A second upload retires the first object, so storage does not accumulate one
// avatar per request.
func TestUploadAvatarDeletesSupersededObject(t *testing.T) {
	service, _, store, _, _ := avatarService(t)
	first := testImageBytes(t, "png")
	second := testImageBytes(t, "jpeg")

	firstResult, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(first), Size: int64(len(first)),
	})
	if err != nil {
		t.Fatalf("first upload: %v", err)
	}
	if _, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(second), Size: int64(len(second)),
	}); err != nil {
		t.Fatalf("second upload: %v", err)
	}
	firstKey := strings.TrimPrefix(firstResult.AvatarURL, "https://cdn.example.com/")
	if !slices.Contains(store.deleted, firstKey) {
		t.Fatalf("deleted keys = %v, want to contain first key %q", store.deleted, firstKey)
	}
	if _, ok := store.uploads[firstKey]; ok {
		t.Fatalf("first object %q still present", firstKey)
	}
	if len(store.uploads) != 1 {
		t.Fatalf("uploads = %d, want 1 (only the newest)", len(store.uploads))
	}
}

// A previous avatar URL that does not belong to this service's storage (e.g.
// migrated from elsewhere) must be left alone, not deleted by guesswork.
func TestUploadAvatarLeavesForeignPreviousURLAlone(t *testing.T) {
	service, users, store, _, _ := avatarService(t)
	users.byID[42].Profile.Avatar = stringPtr("https://legacy.example.net/old/avatar.png")
	imageData := testImageBytes(t, "png")

	if _, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
	}); err != nil {
		t.Fatalf("UploadAvatar returned error: %v", err)
	}
	if len(store.deleted) != 0 {
		t.Fatalf("deleted keys = %v, want none for a foreign URL", store.deleted)
	}
}

func TestUploadAvatarRejectsDeletedUser(t *testing.T) {
	service, users, store, _, _ := avatarService(t)
	users.byID[42].State = model.UserStateDeleted
	imageData := testImageBytes(t, "png")

	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
	})
	if !isKind(err, KindUserDeleted) {
		t.Fatalf("error = %v, want user deleted", err)
	}
	if len(store.uploads) != 0 {
		t.Fatalf("store has %d uploads, want 0", len(store.uploads))
	}
}

func TestUploadAvatarRejectsUnknownUser(t *testing.T) {
	service, _, store, _, _ := avatarService(t)
	imageData := testImageBytes(t, "png")

	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 999, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
	})
	if !isKind(err, KindInvalidToken) {
		t.Fatalf("error = %v, want invalid token", err)
	}
	if len(store.uploads) != 0 {
		t.Fatalf("store has %d uploads, want 0", len(store.uploads))
	}
}

// avatarKeyFromURL must only yield keys it can prove belong to this service's
// storage base.
func TestAvatarKeyFromURL(t *testing.T) {
	newURL := "https://cdn.example.com/avatar/42/abc.jpg"
	key := "avatar/42/abc.jpg"
	cases := []struct {
		name string
		old  string
		want string
	}{
		{"same base", "https://cdn.example.com/avatar/42/old.png", "avatar/42/old.png"},
		{"same key", newURL, ""},
		{"foreign host", "https://other.example.com/avatar/42/old.png", ""},
		{"foreign path", "https://cdn.example.com/upload/42/old.png", ""},
		{"traversal", "https://cdn.example.com/avatar/../secret/keys", ""},
	}
	for _, tc := range cases {
		if got := avatarKeyFromURL(tc.old, newURL, key); got != tc.want {
			t.Fatalf("%s: avatarKeyFromURL(%q) = %q, want %q", tc.name, tc.old, got, tc.want)
		}
	}
}

func isKind(err error, kind Kind) bool {
	var serviceErr *Error
	return errors.As(err, &serviceErr) && serviceErr.Kind == kind
}

var _ objectstore.ObjectStore = (*fakeAvatarStore)(nil)
var _ objectstore.AvatarAuditor = (*fakeAvatarAuditor)(nil)

// Keep the repository import exercised by the fake usage above even if a
// future refactor removes a direct reference.
var _ = repository.ErrNotFound
