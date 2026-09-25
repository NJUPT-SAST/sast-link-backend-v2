package badge

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// Public render parameters.
const (
	renderCacheTTL     = 5 * time.Minute
	renderCacheMax     = 256
	renderCacheEvict   = 64
	renderAvatarBudget = avatarFetchTimeout + time.Second
)

// RenderResult is one rendered badge answer.
type RenderResult struct {
	SVG      []byte
	ETag     string
	NotFound bool
}

// renderCache is a bounded TTL map. It absorbs friend-link wall bursts (many
// distinct viewers, one origin) without a second cache tier; entries expire
// with the same horizon as the response's max-age, so a profile edit lands
// within the same window either way. Per-instance: each API replica warms
// its own, which the hit pattern tolerates.
type renderCache struct {
	mu      sync.Mutex
	entries map[string]renderCacheEntry
}

type renderCacheEntry struct {
	svg      []byte
	etag     string
	notFound bool
	storedAt time.Time
}

func newRenderCache() *renderCache {
	return &renderCache{entries: make(map[string]renderCacheEntry)}
}

func (c *renderCache) get(key string) (renderCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || time.Since(entry.storedAt) > renderCacheTTL {
		return renderCacheEntry{}, false
	}
	return entry, true
}

// purge drops the cached render for one badge key. Called when a badge
// is disabled so the public endpoint
// flips to the 404 error card immediately instead of after the TTL.
func (c *renderCache) purge(badgeKey string) {
	if badgeKey == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	suffix := "|" + badgeKey
	for k := range c.entries {
		if strings.HasSuffix(k, suffix) {
			delete(c.entries, k)
		}
	}
}

func (c *renderCache) put(key string, entry renderCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= renderCacheMax {
		// Evict expired entries first; if the cache is still full, drop a
		// bulk of arbitrary victims — the TTL refills it within minutes and
		// an exact LRU is not worth the bookkeeping at this scale.
		now := time.Now()
		for k, v := range c.entries {
			if now.Sub(v.storedAt) > renderCacheTTL {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= renderCacheMax {
			dropped := 0
			for k := range c.entries {
				delete(c.entries, k)
				dropped++
				if dropped >= renderCacheEvict {
					break
				}
			}
		}
	}
	c.entries[key] = entry
}

// RenderInput names one public render request.
type RenderInput struct {
	Key      string
	Theme    string
	ClientIP string
}

// renderCacheKey folds the request coordinates into one cache identity.
func renderCacheKey(key string, theme Theme) string {
	return string(theme) + "|" + key
}

// Render resolves a public badge key to its SVG. Unknown, closed or deleted
// badges answer the error card (NotFound=true) so an img embed never cracks;
// the caller pairs it with HTTP 404.
func (s *Service) Render(ctx context.Context, input RenderInput) (*RenderResult, error) {
	theme := Theme(input.Theme)
	switch theme {
	case ThemeLight, ThemeDark, ThemeAuto:
	default:
		theme = ThemeAuto
	}

	if input.Key == "" {
		return &RenderResult{SVG: renderErrorCard(), NotFound: true}, nil
	}
	s.renderCacheOnce.Do(func() {
		if s.renderCache == nil {
			s.renderCache = newRenderCache()
		}
	})
	if s.PublicLimiter != nil && input.ClientIP != "" {
		result, err := s.PublicLimiter.Allow(ctx, "badge_public", input.ClientIP)
		if err != nil {
			slog.WarnContext(ctx, "badge public limiter unavailable, allowing request", "error", err)
		} else if !result.Allowed {
			return nil, withRetryAfter(newError(ErrRateLimited, "badge render rate limited", nil), result.RetryAfter)
		}
	}

	cacheKey := renderCacheKey(input.Key, theme)
	if entry, ok := s.renderCache.get(cacheKey); ok {
		return &RenderResult{SVG: entry.svg, ETag: entry.etag, NotFound: entry.notFound}, nil
	}

	badge, err := s.Badges.FindBadgeTarget(ctx, input.Key)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			result := &RenderResult{SVG: renderErrorCard(), NotFound: true}
			s.renderCache.put(cacheKey, renderCacheEntry{svg: result.SVG, notFound: true, storedAt: s.Clock.Now()})
			return result, nil
		}
		return nil, newError(ErrInternal, "render badge: resolve key", err)
	}

	card, err := s.Users.FindPublicCardByUserID(ctx, badge.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// The badge row outlived the user's visibility (deleted between
			// the two reads, or data drift); the error card is the honest
			// answer.
			result := &RenderResult{SVG: renderErrorCard(), NotFound: true}
			s.renderCache.put(cacheKey, renderCacheEntry{svg: result.SVG, notFound: true, storedAt: s.Clock.Now()})
			return result, nil
		}
		return nil, newError(ErrInternal, "render badge: load card", err)
	}

	data := buildCardData(card)
	avatarURL := ""
	if card.Avatar != nil {
		avatarURL = strings.TrimSpace(*card.Avatar)
	}
	if avatarURL != "" && !avatarURLAllowed(avatarURL, s.AvatarHostAllowlist) {
		// Defense in depth: the URL was minted by this service's upload path,
		// but the server-side fetch stays pinned to the configured storage
		// origin. A non-allowlisted avatar renders the initial mark.
		slog.WarnContext(ctx, "badge avatar origin not allowed, using initial mark",
			"user_id", badge.UserID)
		avatarURL = ""
	}
	if avatarURL != "" {
		fetchCtx, cancel := context.WithTimeout(ctx, renderAvatarBudget)
		dataURI, fetchErr := fetchAvatarThumbnail(fetchCtx, avatarURL)
		cancel()
		if fetchErr == nil {
			data.AvatarDataURI = dataURI
		} else {
			// The initial-letter mark already covers the slot; a fetch failure
			// is logged for observability, not surfaced — the badge renders
			// either way.
			slog.WarnContext(ctx, "badge avatar fetch failed, using initial mark",
				"user_id", badge.UserID, "error", fetchErr)
		}
	}

	svg, err := renderCard(theme, data)
	if err != nil {
		return nil, newError(ErrInternal, "render badge: render", err)
	}
	result := &RenderResult{SVG: svg, ETag: etag(svg)}
	s.renderCache.put(cacheKey, renderCacheEntry{svg: svg, etag: result.ETag, storedAt: s.Clock.Now()})
	return result, nil
}

// httpLinkTarget reports whether raw is an absolute http(s) URL — the only
// schemes the rendered card's anchor may carry. The profile fields behind it
// are length- and control-checked at write time but not scheme-checked, and
// xml/html escaping cannot neuter a scheme: "javascript:" (and its
// tab-smuggled "java\tscript:" cousin, which browsers' URL parsing strips
// back to javascript) survives every escaper and executes wherever the SVG is
// inlined without this response's CSP. A non-http target drops the link and
// keeps the card.
func httpLinkTarget(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

// buildCardData projects a public card into display-ready fields: department
// gets its Chinese label, every text field is truncated to the largest
// canvas's bounds (renderCard clamps further per size), and the social links
// collapse into one display line.
func buildCardData(card *repository.PublicCard) cardData {
	data := cardData{Brand: "SAST Link"}

	nickname := ""
	if card.Nickname != nil {
		nickname = strings.TrimSpace(*card.Nickname)
	}
	data.Nickname = truncate(nickname, compactLayout.NameMax)
	if data.Nickname == "" {
		// The enable gate refuses a missing nickname, so this only guards
		// against data drift; the placeholder keeps the canvas honest.
		data.Nickname = "SAST 成员"
	}
	data.AvatarInitial = firstRune(data.Nickname)

	if card.Intro != nil {
		data.Intro = truncate(strings.TrimSpace(*card.Intro), compactLayout.IntroMax)
	}

	blog := ""
	if card.BlogURL != nil && strings.TrimSpace(*card.BlogURL) != "" {
		blog = strings.TrimSpace(*card.BlogURL)
	}
	github := ""
	if card.GitHubURL != nil && strings.TrimSpace(*card.GitHubURL) != "" {
		github = strings.TrimSpace(*card.GitHubURL)
	}
	// The card links to the member's own page — blog first, GitHub as the
	// fallback, nothing when neither exists — and only over http(s): a
	// scheme an escaper cannot neuter (javascript:) must not reach the
	// anchor. The compact canvas has no social-host row, so the hosts are no
	// longer displayed.
	data.LinkTarget = ""
	if httpLinkTarget(blog) {
		data.LinkTarget = blog
	} else if httpLinkTarget(github) {
		data.LinkTarget = github
	}
	return data
}
