package badge

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAvatarURLAllowed(t *testing.T) {
	allow := []string{"cdn.example.com", "bucket.cos.ap-shanghai.myqcloud.com"}

	cases := []struct {
		name string
		url  string
		want bool
	}{
		{"allowed host", "https://cdn.example.com/avatar/1.png", true},
		{"host is case-insensitive", "https://CDN.EXAMPLE.COM/a.png", true},
		{"other host", "https://evil.example.com/a.png", false},
		{"plain http", "http://cdn.example.com/a.png", false},
		{"garbage", "not a url", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		if got := avatarURLAllowed(c.url, allow); got != c.want {
			t.Fatalf("%s: avatarURLAllowed(%q) = %v, want %v", c.name, c.url, got, c.want)
		}
	}

	// An empty allowlist disables remote fetching entirely (fail-closed).
	if avatarURLAllowed("https://cdn.example.com/a.png", nil) {
		t.Fatalf("empty allowlist must refuse every origin")
	}
}

// pngWithDimensions builds a minimal PNG whose header declares the given
// size — enough for DecodeConfig to read dimensions without a full body.
func pngWithDimensions(w, h int) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	writeChunk := func(typ string, data []byte) {
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], uint32(len(data))) // #nosec G115 -- fixture helper; the length is always the fixed 13-byte IHDR
		buf.Write(prefix[:])
		buf.WriteString(typ)
		buf.Write(data)
		sum := crc32.ChecksumIEEE(append(append([]byte{}, typ...), data...))
		var trailer [4]byte
		binary.BigEndian.PutUint32(trailer[:], sum)
		buf.Write(trailer[:])
	}
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], uint32(w)) // #nosec G115 -- fixture helper; callers pass small constants
	binary.BigEndian.PutUint32(ihdr[4:8], uint32(h)) // #nosec G115 -- fixture helper; callers pass small constants
	ihdr[8] = 8                                      // bit depth
	ihdr[9] = 2                                      // truecolor
	writeChunk("IHDR", ihdr)
	return buf.Bytes()
}

func TestFetchRejectsOversizedAvatarDimensions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pngWithDimensions(8000, 8000)) // header claims far over the 4096 cap
	}))
	defer server.Close()

	if _, err := fetchAvatarThumbnail(context.Background(), server.URL); err == nil {
		t.Fatalf("oversized avatar accepted")
	}
}

func TestFetchEmbedsSmallAvatarsAsDataURI(t *testing.T) {
	var img image.Image = image.NewRGBA(image.Rect(0, 0, 64, 64))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	defer server.Close()

	dataURI, err := fetchAvatarThumbnail(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("fetch error = %v", err)
	}
	if len(dataURI) == 0 || dataURI[:22] != "data:image/png;base64," {
		t.Fatalf("unexpected data URI prefix: %q", dataURI[:30])
	}
}
