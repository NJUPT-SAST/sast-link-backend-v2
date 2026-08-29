package objectstore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/objectstore"
)

// The package ships no implementation, so the interface contracts are pinned by
// an in-memory fake plus the exercise functions below. An implementation that
// lands later (COS today, anything else tomorrow) can reuse the same assertion
// set against its own store.
//
// memStore keeps its contract deliberately strict: the declared Upload size is
// the exact byte count, and a mismatch is a rejected write rather than a silent
// truncation.
type memObject struct {
	data        []byte
	contentType string
}

type memStore struct {
	mu      sync.Mutex
	objects map[string]memObject
}

func newMemStore() *memStore {
	return &memStore{objects: make(map[string]memObject)}
}

const memScheme = "mem://"

func (s *memStore) Upload(ctx context.Context, key string, r io.Reader, contentType string, size int64) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(r, size+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) != size {
		return "", errors.New("size mismatch: reader length differs from declared size")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = memObject{data: data, contentType: contentType}
	return memScheme + key, nil
}

func (s *memStore) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, key)
	return nil
}

// getURL simulates the public read path the uploaded URL advertises: the object
// stored under the key encoded in url comes back byte-identical.
func (s *memStore) getURL(url string) ([]byte, error) {
	if !strings.HasPrefix(url, memScheme) {
		return nil, errors.New("unexpected url scheme")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[strings.TrimPrefix(url, memScheme)]
	if !ok {
		return nil, errors.New("object not found")
	}
	return obj.data, nil
}

func (s *memStore) contentTypeOf(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.objects[key].contentType
}

type failReader struct{ err error }

func (r *failReader) Read([]byte) (int, error) { return 0, r.err }

func uploadBytes(t *testing.T, store objectstore.ObjectStore, key, contentType string, content []byte) string {
	t.Helper()
	url, err := store.Upload(context.Background(), key, bytes.NewReader(content), contentType, int64(len(content)))
	if err != nil {
		t.Fatalf("Upload(%q): %v", key, err)
	}
	return url
}

// exerciseObjectStoreContract is the shared assertion set for ObjectStore
// implementations. urlGet reads the object back through the URL Upload returned,
// which is exactly the path a public display card or OIDC picture claim uses.
func exerciseObjectStoreContract(t *testing.T, store objectstore.ObjectStore, urlGet func(string) ([]byte, error)) {
	t.Helper()

	t.Run("upload returns a stable url whose content roundtrips", func(t *testing.T) {
		const key = "avatars/contract-a.png"
		const content = "\x89PNG\r\n\x1a\ncontract image a"
		url := uploadBytes(t, store, key, "image/png", []byte(content))
		if url != memScheme+key {
			t.Errorf("url = %q, want %q", url, memScheme+key)
		}
		got, err := urlGet(url)
		if err != nil {
			t.Fatalf("content at url: %v", err)
		}
		if !bytes.Equal(got, []byte(content)) {
			t.Errorf("content = %q, want %q", got, content)
		}

		// Re-uploading the same key keeps the url stable but swaps the content.
		replaced := "replacement for a"
		again, err := store.Upload(context.Background(), key, strings.NewReader(replaced), "image/png", int64(len(replaced)))
		if err != nil {
			t.Fatalf("re-upload: %v", err)
		}
		if again != url {
			t.Errorf("re-upload url = %q, want %q", again, url)
		}
		gotAgain, err := urlGet(url)
		if err != nil {
			t.Fatalf("content after re-upload: %v", err)
		}
		if !bytes.Equal(gotAgain, []byte(replaced)) {
			t.Errorf("content after re-upload = %q, want %q", gotAgain, replaced)
		}
	})

	t.Run("empty object roundtrips", func(t *testing.T) {
		url := uploadBytes(t, store, "avatars/contract-empty.png", "application/octet-stream", nil)
		got, err := urlGet(url)
		if err != nil {
			t.Fatalf("content at url: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("content = %q, want empty", got)
		}
	})

	t.Run("size mismatch is rejected without corrupting the object", func(t *testing.T) {
		const key = "avatars/contract-size.png"
		const content = "0123456789"
		url := uploadBytes(t, store, key, "image/png", []byte(content))

		if _, err := store.Upload(context.Background(), key, strings.NewReader(content), "image/png", 99); err == nil {
			t.Fatal("Upload: expected error for size larger than the reader")
		}
		if _, err := store.Upload(context.Background(), key, strings.NewReader(content), "image/png", 3); err == nil {
			t.Fatal("Upload: expected error for size smaller than the reader")
		}

		got, err := urlGet(url)
		if err != nil {
			t.Fatalf("content after rejected writes: %v", err)
		}
		if !bytes.Equal(got, []byte(content)) {
			t.Errorf("content after rejected writes = %q, want the original %q", got, content)
		}
	})

	t.Run("reader error fails the upload", func(t *testing.T) {
		boom := errors.New("read failed")
		_, err := store.Upload(context.Background(), "avatars/contract-fail.png", &failReader{err: boom}, "image/png", 3)
		if err == nil {
			t.Fatal("Upload: expected error from a failing reader")
		}
		if !errors.Is(err, boom) {
			t.Errorf("Upload: error = %v, want %v", err, boom)
		}
	})

	t.Run("canceled context fails the upload and writes nothing", func(t *testing.T) {
		const key = "avatars/contract-cancel.png"
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := store.Upload(ctx, key, strings.NewReader("data"), "image/png", 4)
		if err == nil {
			t.Fatal("Upload: expected error for a canceled context")
		}
		if _, err := urlGet(memScheme + key); err == nil {
			t.Error("Upload: canceled write left an object behind")
		}
	})

	t.Run("delete is idempotent and removes the content", func(t *testing.T) {
		const key = "avatars/contract-del.png"
		url := uploadBytes(t, store, key, "image/png", []byte("delete me"))
		if err := store.Delete(context.Background(), key); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := urlGet(url); err == nil {
			t.Error("Delete: object still reachable after delete")
		}
		// Deleting a key that does not exist is the desired end state, not an error.
		if err := store.Delete(context.Background(), key); err != nil {
			t.Errorf("Delete (second): %v, want nil", err)
		}
		if err := store.Delete(context.Background(), "avatars/never-written.png"); err != nil {
			t.Errorf("Delete (never existed): %v, want nil", err)
		}
		// A deleted key can be written again and stays reachable.
		uploadBytes(t, store, key, "image/png", []byte("born again"))
		got, err := urlGet(url)
		if err != nil {
			t.Fatalf("content after re-upload: %v", err)
		}
		if !bytes.Equal(got, []byte("born again")) {
			t.Errorf("content after re-upload = %q, want %q", got, "born again")
		}
	})

	t.Run("canceled context fails the delete and keeps the object", func(t *testing.T) {
		const key = "avatars/contract-del-cancel.png"
		url := uploadBytes(t, store, key, "image/png", []byte("keep me"))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := store.Delete(ctx, key); err == nil {
			t.Fatal("Delete: expected error for a canceled context")
		}
		if _, err := urlGet(url); err != nil {
			t.Errorf("Delete: object was removed despite the canceled context: %v", err)
		}
	})
}

func TestObjectStoreContract(t *testing.T) {
	store := newMemStore()
	exerciseObjectStoreContract(t, store, store.getURL)
}

// The content type is not part of the ObjectStore contract's observable read
// path, so it is pinned here directly against the fake rather than in the
// shared exercise.
func TestUploadRecordsContentType(t *testing.T) {
	store := newMemStore()
	const key = "avatars/content-type.png"
	url, err := store.Upload(context.Background(), key, strings.NewReader("img"), "image/png", 3)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if url == "" {
		t.Fatal("Upload: empty url")
	}
	if got := store.contentTypeOf(key); got != "image/png" {
		t.Errorf("content type = %q, want image/png", got)
	}
}

type stubAuditor struct {
	result objectstore.AuditResult
	err    error
}

func (s stubAuditor) AuditImage(context.Context, string) (objectstore.AuditResult, error) {
	return s.result, s.err
}

// AvatarAuditor is fail-closed by contract: a non-nil error means the review did
// not happen and the caller must treat the upload as rejected. The table pins the
// result struct's behaviour — Sensitive/Label verdicts passing through verbatim,
// and an unreachable review surface surfacing as an error.
func TestAvatarAuditorContract(t *testing.T) {
	boom := errors.New("review service unreachable")
	cases := []struct {
		name    string
		auditor objectstore.AvatarAuditor
		want    objectstore.AuditResult
		wantErr bool
	}{
		{
			name:    "clear image returns a non-sensitive verdict",
			auditor: stubAuditor{result: objectstore.AuditResult{Sensitive: false, Label: "Normal"}},
			want:    objectstore.AuditResult{Sensitive: false, Label: "Normal"},
		},
		{
			name:    "hit scene is sensitive and carries a label",
			auditor: stubAuditor{result: objectstore.AuditResult{Sensitive: true, Label: "Porn"}},
			want:    objectstore.AuditResult{Sensitive: true, Label: "Porn"},
		},
		{
			name:    "zero-value verdict is clear",
			auditor: stubAuditor{},
			want:    objectstore.AuditResult{},
		},
		{
			name:    "unavailable review service fails the audit",
			auditor: stubAuditor{err: boom},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.auditor.AuditImage(context.Background(), "avatars/audit.png")
			if tc.wantErr {
				if err == nil {
					t.Fatal("AuditImage: expected error, got nil")
				}
				if !errors.Is(err, boom) {
					t.Errorf("AuditImage: error = %v, want %v", err, boom)
				}
				return
			}
			if err != nil {
				t.Fatalf("AuditImage: unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("AuditImage: result = %+v, want %+v", got, tc.want)
			}
		})
	}
}
