package badge

import (
	"context"
	"encoding/base64"
	"errors"
	"hash/maphash"
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
	renderFillLanes    = 8
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
// after five minutes so profile edits propagate within that window. Sharing
// visibility is checked live for every response, independently of this cache.
type renderCache struct {
	mu      sync.Mutex
	entries map[string]renderCacheEntry
	seed    maphash.Seed
	fills   [renderFillLanes]chan struct{}
}

type renderCacheEntry struct {
	svg      []byte
	etag     string
	storedAt time.Time
}

func newRenderCache() *renderCache {
	c := &renderCache{entries: make(map[string]renderCacheEntry), seed: maphash.MakeSeed()}
	for i := range c.fills {
		c.fills[i] = make(chan struct{}, 1)
	}
	return c
}

// lockFill bounds expensive profile/avatar/render work to eight concurrent fills.
// Fixed hash lanes avoid a map or goroutine per attacker-chosen key. Collisions
// may queue unrelated cold badges, but never serialize the warm path. The
// random seed prevents callers from deliberately selecting one busy lane.
func (c *renderCache) lockFill(ctx context.Context, key string) (func(), error) {
	lane := c.fills[maphash.String(c.seed, key)%uint64(len(c.fills))]
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case lane <- struct{}{}:
		return func() { <-lane }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
// changes sharing periods, so a resumed badge reloads its display data.
// Privacy is enforced by live database checks, not local invalidation.
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

	// Bound cache-key memory before any database lookup or cache insertion.
	if input.Key == "" || len(input.Key) > base64.RawURLEncoding.EncodedLen(badgeKeyBytes) {
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
	badge, err := s.Badges.FindBadgeTarget(ctx, input.Key)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			result := &RenderResult{SVG: renderErrorCard(), NotFound: true}
			return result, nil
		}
		return nil, newError(ErrInternal, "render badge: resolve key", err)
	}

	// Authorization is always live, including on a render-cache hit: another
	// instance may have disabled sharing, or an admin may have closed the user.
	if entry, ok := s.renderCache.get(cacheKey); ok {
		return &RenderResult{SVG: entry.svg, ETag: entry.etag}, nil
	}

	result, err := s.fillRenderCache(ctx, badge.UserID, theme, cacheKey)
	if err != nil || result.NotFound {
		return result, err
	}
	// Waiting and avatar fetching can take seconds. Visibility is individual
	// to this request and must never be shared with the preceding fill.
	if _, visibilityErr := s.Badges.FindBadgeTarget(ctx, input.Key); visibilityErr != nil {
		if errors.Is(visibilityErr, repository.ErrNotFound) {
			return &RenderResult{SVG: renderErrorCard(), NotFound: true}, nil
		}
		return nil, newError(ErrInternal, "render badge: final visibility", visibilityErr)
	}
	return result, nil
}

// Only display work holds the lane. Followers revalidate outside it, allowing
// their database round trips to overlap. Deferred release also survives panic
// recovery by the HTTP middleware.
func (s *Service) fillRenderCache(ctx context.Context, userID int64, theme Theme, cacheKey string) (*RenderResult, error) {
	unlock, err := s.renderCache.lockFill(ctx, cacheKey)
	if err != nil {
		return nil, newError(ErrInternal, "render badge: wait for fill", err)
	}
	defer unlock()
	if entry, ok := s.renderCache.get(cacheKey); ok {
		return &RenderResult{SVG: entry.svg, ETag: entry.etag}, nil
	}
	return s.renderCold(ctx, userID, theme, cacheKey)
}

func (s *Service) renderCold(ctx context.Context, userID int64, theme Theme, cacheKey string) (*RenderResult, error) {
	card, err := s.Users.FindPublicCardByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// The badge row outlived the user's visibility (deleted between
			// the two reads, or data drift); the error card is the honest
			// answer.
			result := &RenderResult{SVG: renderErrorCard(), NotFound: true}
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
			"user_id", userID)
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
				"user_id", userID, "error", fetchErr)
		}
	}

	svg, err := renderCard(theme, data)
	if err != nil {
		return nil, newError(ErrInternal, "render badge: render", err)
	}
	result := &RenderResult{SVG: svg, ETag: etag(svg)}
	s.renderCache.put(cacheKey, renderCacheEntry{svg: svg, etag: result.ETag, storedAt: time.Now()})
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

// buildCardData projects public profile fields onto the compact canvas and
// selects a safe link target without exposing identity or department fields.
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
