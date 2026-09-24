package badge

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	_ "image/jpeg"
	"image/png"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/disintegration/imaging"
	_ "golang.org/x/image/webp"
)

// Avatar fetch and embed parameters. GitHub's camo proxy strips external
// resource references from an embedded SVG, so the avatar must ride inside
// the document as a data URI; the thumbnail bounds its weight.
const (
	avatarFetchTimeout = 2 * time.Second
	avatarMaxBytes     = 1 << 20 // 1MB
	avatarThumbnail    = 128     // px, square fit
)

// avatarHTTPClient is shared across renders. It never follows redirects — a
// redirect chain on a user-controlled avatar URL is unbounded work — and its
// timeout bounds the whole render path.
var avatarHTTPClient = &http.Client{
	Timeout: avatarFetchTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// fetchAvatarThumbnail downloads the avatar URL, shrinks it to a square
// thumbnail and returns it as a PNG data URI. Any failure is an error — the
// caller falls back to the initial-letter mark, which is a rendering decision
// rather than a fetch one.
func fetchAvatarThumbnail(ctx context.Context, avatarURL string) (string, error) {
	if strings.TrimSpace(avatarURL) == "" {
		return "", fmt.Errorf("avatar url empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, avatarURL, nil)
	if err != nil {
		return "", fmt.Errorf("build avatar request: %w", err)
	}
	resp, err := avatarHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch avatar: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch avatar: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, avatarMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("read avatar: %w", err)
	}
	if len(body) > avatarMaxBytes {
		return "", fmt.Errorf("read avatar: exceeds %d bytes", avatarMaxBytes)
	}

	decoded, _, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("decode avatar: %w", err)
	}

	thumbnail := imaging.Fit(decoded, avatarThumbnail, avatarThumbnail, imaging.Lanczos)
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, thumbnail); err != nil {
		return "", fmt.Errorf("encode avatar thumbnail: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(encoded.Bytes()), nil
}
