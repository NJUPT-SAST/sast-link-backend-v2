package session

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"os"
	"path/filepath"
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
		// A real, decodable WebP from golang.org/x/image's own testdata; the
		// re-encode path decodes full pixels, so a header-only fixture would fail.
		raw, err := os.ReadFile(filepath.Join("testdata", "webp_fixture.webp"))
		if err != nil {
			t.Fatalf("read webp fixture: %v", err)
		}
		return raw
	default:
		t.Fatalf("unknown test format %q", format)
	}
	return buf.Bytes()
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

// An image with a polyglot trailer (magic-valid image prefix + HTML/JS tail)
// must be re-encoded to clean pixels before storage, so the tail never reaches
// the bucket (audit finding #9).
func TestUploadAvatarStripsPolyglotTrailer(t *testing.T) {
	service, _, store, _, _ := avatarService(t)
	imageData := append(testImageBytes(t, "png"), []byte("<script>alert(1)</script>")...)

	if _, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
	}); err != nil {
		t.Fatalf("UploadAvatar returned error: %v", err)
	}
	if len(store.uploads) != 1 {
		t.Fatalf("uploads = %d, want 1", len(store.uploads))
	}
	var stored []byte
	for _, data := range store.uploads {
		stored = data
	}
	if bytes.Contains(stored, []byte("<script>")) {
		t.Fatal("stored avatar still contains the polyglot trailer")
	}
	if _, _, err := image.Decode(bytes.NewReader(stored)); err != nil {
		t.Fatalf("re-encoded avatar does not decode: %v", err)
	}
}

// A phone photo carries an EXIF orientation tag the stdlib JPEG decoder ignores;
// the re-encode must bake the correction in, or the stored PNG comes out sideways
// (audit-fix follow-up).
func TestUploadAvatarAppliesEXIFOrientation(t *testing.T) {
	service, _, store, _, _ := avatarService(t)
	// A 4-wide by 8-tall JPEG claiming orientation 6 (rotate 90° to correct):
	// the stored PNG must have the correction applied (8 wide, 4 tall), not the
	// raw sideways pixels stdlib image/jpeg would hand over.
	imageData := testJPEGWithOrientation(t, 4, 8, 6)

	if _, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(imageData), Size: int64(len(imageData)),
	}); err != nil {
		t.Fatalf("UploadAvatar: %v", err)
	}
	var stored []byte
	for _, data := range store.uploads {
		stored = data
	}
	decoded, _, err := image.Decode(bytes.NewReader(stored))
	if err != nil {
		t.Fatalf("stored PNG does not decode: %v", err)
	}
	// Orientation 6 is a 90° transform, so width and height swap.
	if bounds := decoded.Bounds(); bounds.Dx() != 8 || bounds.Dy() != 4 {
		t.Fatalf("stored PNG bounds = %dx%d, want 8x4 (orientation applied)", bounds.Dx(), bounds.Dy())
	}
}

// testJPEGWithOrientation builds a WxH JPEG whose EXIF orientation tag claims
// the given value, so the re-encode path's AutoOrientation step is exercised.
func testJPEGWithOrientation(t *testing.T, w, h, orientation int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	var raw bytes.Buffer
	if err := jpeg.Encode(&raw, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("encode base jpeg: %v", err)
	}
	base := raw.Bytes()
	app1 := append([]byte("Exif\x00\x00"), buildOrientationTIFF(orientation)...)
	out := make([]byte, 0, len(base)+len(app1)+4)
	out = append(out, base[:2]...)                                     // SOI
	out = append(out, 0xFF, 0xE1, byte(len(app1)>>8), byte(len(app1))) // #nosec G115 — segment length is 32, far below 256
	out = append(out, app1...)
	out = append(out, base[2:]...)
	return out
}

// buildOrientationTIFF returns the minimal TIFF block an EXIF APP1 segment needs
// to carry an orientation tag (IFD0 entry 0x0112, SHORT, value 1-8).
func buildOrientationTIFF(orientation int) []byte {
	tiff := []byte{'I', 'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00} // little-endian, IFD0 at offset 8
	tiff = append(tiff, 0x01, 0x00)                              // one IFD entry
	tiff = append(tiff,
		0x12, 0x01, // tag 0x0112 (orientation)
		0x03, 0x00, // type 3 (SHORT)
		0x01, 0x00, 0x00, 0x00, // count 1
		byte(orientation), 0x00, 0x00, 0x00, // #nosec G115 — orientation is 1-8
	)
	tiff = append(tiff, 0x00, 0x00, 0x00, 0x00) // no more IFDs
	return tiff
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

// A valid image whose header declares a dimension beyond maxAvatarDimension must
// be rejected before the content review sees it. DecodeConfig reads only the
// header, so this also proves the guard needs no pixel data.
func TestUploadAvatarRejectsOversizedDimensions(t *testing.T) {
	service, _, store, _, _ := avatarService(t)
	big := image.NewRGBA(image.Rect(0, 0, maxAvatarDimension+1, 10))
	var buf bytes.Buffer
	if err := png.Encode(&buf, big); err != nil {
		t.Fatalf("encode oversized png: %v", err)
	}
	_, err := service.UploadAvatar(context.Background(), UploadAvatarInput{
		UserID: 42, Content: bytes.NewReader(buf.Bytes()), Size: int64(buf.Len()),
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
	if !errors.As(err, &serviceErr) || serviceErr.Code != errcode.CodeAvatarRejected {
		t.Fatalf("error = %v, want avatar-rejected code", err)
	}
	if len(store.uploads) != 0 {
		t.Fatalf("store still has %d objects, want 0 after rejection", len(store.uploads))
	}
	if got := users.byID[42].Profile.Avatar; got != nil {
		t.Fatalf("profile.avatar = %v, want nil after rejection", *got)
	}
	entry := audit.entries[len(audit.entries)-1]
	if entry.Action != "upload_avatar" || entry.Success == nil || *entry.Success || entry.ErrCode == nil || *entry.ErrCode != errcode.CodeAvatarRejected {
		t.Fatalf("audit entry = %+v, want failed upload_avatar with 42203", entry)
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
	if !errors.As(err, &serviceErr) || serviceErr.Code != errcode.CodeDependencyUnavailable {
		t.Fatalf("error = %v, want dependency-unavailable code", err)
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
