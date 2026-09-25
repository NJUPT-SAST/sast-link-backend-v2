package badge

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func strPtr(v string) *string { return &v }

func renderForTest(t *testing.T, theme Theme, data cardData) string {
	t.Helper()
	svg, err := renderCard(theme, data)
	if err != nil {
		t.Fatalf("renderCard error = %v", err)
	}
	return string(svg)
}

func TestRenderCardCompactCanvas(t *testing.T) {
	svg := renderForTest(t, ThemeLight, cardData{Nickname: "张三", AvatarInitial: "张"})
	if !strings.Contains(svg, `width="320"`) || !strings.Contains(svg, `height="72"`) {
		t.Fatalf("compact canvas missing from output")
	}
}

func TestRenderCardEmptyFieldsKeepSlots(t *testing.T) {
	// A card with only a nickname still renders the exact same canvas — the
	// signature slot is simply empty.
	full := renderForTest(t, ThemeLight, cardData{Nickname: "张三", Intro: "全栈开发"})
	minimal := renderForTest(t, ThemeLight, cardData{Nickname: "张三", AvatarInitial: "张"})

	if !strings.Contains(full, "全栈开发") {
		t.Fatalf("full card lost fields")
	}
	if strings.Contains(minimal, "全栈开发") {
		t.Fatalf("minimal card shows absent fields")
	}
	// Both canvases are 320×72 — the fixed-grid contract.
	if !strings.Contains(minimal, `width="320"`) || !strings.Contains(minimal, `height="72"`) {
		t.Fatalf("minimal card changed the canvas size")
	}
}

func TestRenderCardThemes(t *testing.T) {
	data := cardData{Nickname: "张三"}
	auto := renderForTest(t, ThemeAuto, data)
	light := renderForTest(t, ThemeLight, data)
	dark := renderForTest(t, ThemeDark, data)

	if !strings.Contains(auto, "prefers-color-scheme: dark") {
		t.Fatalf("auto theme missing the dark media query")
	}
	if !strings.Contains(auto, lightPalette.Background) {
		t.Fatalf("auto theme missing the light palette")
	}
	if !strings.Contains(light, "#ffffff") || strings.Contains(light, "prefers-color-scheme") {
		t.Fatalf("light theme should pin the light palette with no media query")
	}
	if !strings.Contains(dark, darkPalette.Background) || strings.Contains(dark, "prefers-color-scheme") {
		t.Fatalf("dark theme should pin the dark palette with no media query")
	}
}

func TestRenderCardEscapesUserText(t *testing.T) {
	data := cardData{Nickname: `<b>&"x"</b>`}
	svg := renderForTest(t, ThemeLight, data)
	if strings.Contains(svg, "<b>") {
		t.Fatalf("raw markup leaked into the SVG: %s", svg)
	}
	if !strings.Contains(svg, "&lt;b&gt;") {
		t.Fatalf("nickname not escaped: %s", svg)
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"short", 10, "short"},
		{"一二三四五六七八九十", 5, "一二三四五…"},
		{"abcdefghij", 5, "abcdefghi…"}, // 9 latin chars ≈ 4.95 slots
		{"", 5, ""},
	}
	for _, c := range cases {
		if got := truncate(c.in, c.max); got != c.want {
			t.Fatalf("truncate(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}

func TestRenderUnknownKeyAnswersErrorCard(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{}}
	service := newTestService(users, newFakeBadgeRepository(), &fakeAuditRepository{})

	result, err := service.Render(context.Background(), RenderInput{Key: "unknown", Theme: "auto"})
	if err != nil {
		t.Fatalf("Render error = %v", err)
	}
	if !result.NotFound {
		t.Fatalf("Render(unknown) NotFound = false, want true")
	}
	if !strings.Contains(string(result.SVG), "徽标不存在或已关闭") {
		t.Fatalf("error card copy missing: %s", result.SVG)
	}
}

func TestRenderKnownKeyProducesSVGWithCard(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{
		7: {Nickname: strPtr("张三"), Intro: strPtr("全栈开发")},
	}}
	badges := newFakeBadgeRepository()
	if err := badges.Create(context.Background(), &model.Badge{UserID: 7, BadgeKey: "render-key"}); err != nil {
		t.Fatalf("seed badge error = %v", err)
	}
	service := newTestService(users, badges, &fakeAuditRepository{})

	result, err := service.Render(context.Background(), RenderInput{Key: "render-key", Theme: "dark"})
	if err != nil {
		t.Fatalf("Render error = %v", err)
	}
	if result.NotFound {
		t.Fatalf("Render(known key) NotFound = true")
	}
	svg := string(result.SVG)
	if !strings.Contains(svg, "张三") || !strings.Contains(svg, "全栈开发") {
		t.Fatalf("rendered card lost fields: %s", svg)
	}
	if !strings.Contains(svg, "SAST Link") {
		t.Fatalf("rendered card lost the brand mark")
	}
	if result.ETag == "" {
		t.Fatalf("rendered card missing the ETag")
	}
}

func TestRenderCachesIdenticalRequests(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{
		7: {Nickname: strPtr("张三")},
	}}
	badges := newFakeBadgeRepository()
	if err := badges.Create(context.Background(), &model.Badge{UserID: 7, BadgeKey: "cache-key"}); err != nil {
		t.Fatalf("seed badge error = %v", err)
	}
	service := newTestService(users, badges, &fakeAuditRepository{})

	first, err := service.Render(context.Background(), RenderInput{Key: "cache-key", Theme: "auto"})
	if err != nil {
		t.Fatalf("first Render error = %v", err)
	}
	second, err := service.Render(context.Background(), RenderInput{Key: "cache-key", Theme: "auto"})
	if err != nil {
		t.Fatalf("second Render error = %v", err)
	}
	if string(first.SVG) != string(second.SVG) || first.ETag != second.ETag {
		t.Fatalf("cached render diverged")
	}
}

func TestRenderHonorsPublicLimiter(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: {Nickname: strPtr("张三")}}}
	badges := newFakeBadgeRepository()
	if err := badges.Create(context.Background(), &model.Badge{UserID: 7, BadgeKey: "limited-key"}); err != nil {
		t.Fatalf("seed badge error = %v", err)
	}
	limiter := &fakeLimiter{allowed: false, retry: 60e9}
	service := newTestService(users, badges, &fakeAuditRepository{})
	service.PublicLimiter = limiter

	_, err := service.Render(context.Background(), RenderInput{Key: "limited-key", ClientIP: "203.0.113.9"})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Render error = %v, want ErrRateLimited", err)
	}
}

func TestRenderUnknownThemeFallsBackToAuto(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: {Nickname: strPtr("张三")}}}
	badges := newFakeBadgeRepository()
	if err := badges.Create(context.Background(), &model.Badge{UserID: 7, BadgeKey: "fallback-key"}); err != nil {
		t.Fatalf("seed badge error = %v", err)
	}
	service := newTestService(users, badges, &fakeAuditRepository{})

	// An unrecognized theme falls back to auto rather than erroring: an img
	// embed cannot show an error envelope to its viewer.
	result, err := service.Render(context.Background(), RenderInput{Key: "fallback-key", Theme: "neon"})
	if err != nil {
		t.Fatalf("Render error = %v", err)
	}
	if result.NotFound || !strings.Contains(string(result.SVG), "prefers-color-scheme") {
		t.Fatalf("fallback render = %s", result.SVG)
	}
}

// TestRenderStartsWithXMLDeclaration pins the html/template regression: the
// whole point of the text/template switch is that the body begins with a real
// <?xml declaration — html/template escaped it to &lt;?xml, and an <img> embed
// refuses to parse a body that does not start with '<'.
func TestRenderStartsWithXMLDeclaration(t *testing.T) {
	svg, err := renderCard(ThemeLight, cardData{Nickname: "张三"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.HasPrefix(string(svg), `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Fatalf("body does not start with the XML declaration: %q", svg[:40])
	}
	if body := string(renderErrorCard()); !strings.HasPrefix(body, `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Fatalf("error card does not start with the XML declaration: %q", body[:40])
	}
}

// TestRenderBorderStaysInsideCanvas pins the missing-right-border regression:
// the hairline rect starts at x=0.5, so its width must be canvas-1 — a full
// width pushes the right stroke outside the viewBox and the browser clips it.
func TestRenderBorderStaysInsideCanvas(t *testing.T) {
	svg := renderForTest(t, ThemeLight, cardData{Nickname: "张三"})
	wantBorder := `x="0.5" y="0.5" width="` + strconv.Itoa(320-1) +
		`" fill="none" stroke="#e5e7eb" height="` + strconv.Itoa(72-1) + `"`
	if !strings.Contains(svg, wantBorder) {
		t.Fatalf("border rect not found as %q", wantBorder)
	}
}

func TestRenderCardLinksToMembersOwnPage(t *testing.T) {
	// Blog wins when both exist.
	withBoth := cardData{Nickname: "张三", LinkTarget: "https://blog.example.com"}
	svg := renderForTest(t, ThemeLight, withBoth)
	if !strings.Contains(svg, `<a href="https://blog.example.com" target="_blank" rel="noopener noreferrer">`) {
		t.Fatalf("card missing the link wrap: %s", svg[:200])
	}
	if !strings.Contains(svg, "</a>") {
		t.Fatalf("card link never closes")
	}

	// No target, no link element at all.
	without := renderForTest(t, ThemeLight, cardData{Nickname: "张三"})
	if strings.Contains(without, "<a ") {
		t.Fatalf("card without a link target must not emit an anchor")
	}
}

func TestBuildCardDataResolvesLinkTarget(t *testing.T) {
	blog := "https://blog.example.com"
	github := "https://github.com/alice"

	withBoth := buildCardData(&repository.PublicCard{Nickname: strPtr("张三"), BlogURL: &blog, GitHubURL: &github})
	if withBoth.LinkTarget != blog {
		t.Fatalf("LinkTarget = %q, want the blog url", withBoth.LinkTarget)
	}
	githubOnly := buildCardData(&repository.PublicCard{Nickname: strPtr("张三"), GitHubURL: &github})
	if githubOnly.LinkTarget != github {
		t.Fatalf("LinkTarget = %q, want the github fallback", githubOnly.LinkTarget)
	}
	neither := buildCardData(&repository.PublicCard{Nickname: strPtr("张三")})
	if neither.LinkTarget != "" {
		t.Fatalf("LinkTarget = %q, want empty", neither.LinkTarget)
	}
}

func TestDisablePurgesRenderCache(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: {Nickname: strPtr("张三")}}}
	badges := newFakeBadgeRepository()
	if err := badges.Create(context.Background(), &model.Badge{UserID: 7, BadgeKey: "purge-key"}); err != nil {
		t.Fatalf("seed badge error = %v", err)
	}
	service := newTestService(users, badges, &fakeAuditRepository{})

	if _, err := service.Render(context.Background(), RenderInput{Key: "purge-key", Theme: "auto"}); err != nil {
		t.Fatalf("warm render error = %v", err)
	}

	if err := service.Disable(context.Background(), DisableInput{UserID: 7}); err != nil {
		t.Fatalf("Disable error = %v", err)
	}

	// The cached render must now answer the closed card — the cache no longer
	// serves the pre-disable render.
	result, err := service.Render(context.Background(), RenderInput{Key: "purge-key", Theme: "auto"})
	if err != nil {
		t.Fatalf("post-disable render error = %v", err)
	}
	if !result.NotFound {
		t.Fatalf("render served a cached render after disable")
	}
}

func TestReEnabledKeyServesTheBadgeAgain(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: {Nickname: strPtr("张三")}}}
	badges := newFakeBadgeRepository()
	service := newTestService(users, badges, &fakeAuditRepository{})

	first, err := service.Enable(context.Background(), EnableInput{UserID: 7})
	if err != nil {
		t.Fatalf("Enable error = %v", err)
	}
	disableErr := service.Disable(context.Background(), DisableInput{UserID: 7})
	if disableErr != nil {
		t.Fatalf("Disable error = %v", disableErr)
	}

	// While paused the key renders the closed card.
	paused, err := service.Render(context.Background(), RenderInput{Key: first.Key, Theme: "auto"})
	if err != nil {
		t.Fatalf("paused Render error = %v", err)
	}
	if !paused.NotFound {
		t.Fatalf("paused badge must render the closed card")
	}

	// The resume must also clear the cached 404 — the same request then
	// serves the badge again under the same key.
	_, resumeErr := service.Enable(context.Background(), EnableInput{UserID: 7})
	if resumeErr != nil {
		t.Fatalf("re-enable error = %v", resumeErr)
	}
	resumed, err := service.Render(context.Background(), RenderInput{Key: first.Key, Theme: "auto"})
	if err != nil {
		t.Fatalf("resumed Render error = %v", err)
	}
	if resumed.NotFound {
		t.Fatalf("resumed badge still renders the closed card: cached 404 not purged")
	}
}
