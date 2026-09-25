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

func renderForTest(t *testing.T, size Size, theme Theme, data cardData) string {
	t.Helper()
	svg, err := renderCard(size, theme, data)
	if err != nil {
		t.Fatalf("renderCard error = %v", err)
	}
	return string(svg)
}

func TestRenderCardFixedCanvasPerSize(t *testing.T) {
	data := cardData{Nickname: "张三", AvatarInitial: "张"}
	for size, want := range map[Size][2]int{
		SizeSM: {320, 72},
		SizeMD: {460, 120},
		SizeLG: {540, 200},
	} {
		svg := renderForTest(t, size, ThemeLight, data)
		if !strings.Contains(svg, `width="`+strconv.Itoa(want[0])+`"`) ||
			!strings.Contains(svg, `height="`+strconv.Itoa(want[1])+`"`) {
			t.Fatalf("%s canvas = (%d,%d) missing from output", size, want[0], want[1])
		}
	}
}

func TestRenderCardEmptyFieldsKeepSlots(t *testing.T) {
	// A card with only a nickname still renders the exact same canvas — the
	// department and intro slots are simply empty.
	full := renderForTest(t, SizeMD, ThemeLight, cardData{
		Nickname: "张三", Intro: "全栈开发", Links: "example.com",
	})
	minimal := renderForTest(t, SizeMD, ThemeLight, cardData{Nickname: "张三", AvatarInitial: "张"})

	if !strings.Contains(full, "全栈开发") {
		t.Fatalf("full card lost fields")
	}
	if strings.Contains(minimal, "全栈开发") {
		t.Fatalf("minimal card shows absent fields")
	}
	// Both canvases are 460×120 — the fixed-grid contract.
	if !strings.Contains(minimal, `width="460"`) || !strings.Contains(minimal, `height="120"`) {
		t.Fatalf("minimal card changed the canvas size")
	}
}

func TestRenderCardSizeDrivenFieldVisibility(t *testing.T) {
	data := cardData{
		Nickname: "张三", Intro: "全栈开发", Links: "blog.example.com",
	}
	sm := renderForTest(t, SizeSM, ThemeLight, data)
	md := renderForTest(t, SizeMD, ThemeLight, data)
	lg := renderForTest(t, SizeLG, ThemeLight, data)

	if strings.Contains(sm, "全栈开发") || strings.Contains(sm, "blog.example.com") {
		t.Fatalf("sm renders intro or links")
	}
	if strings.Contains(md, "blog.example.com") {
		t.Fatalf("md renders links")
	}
	if !strings.Contains(lg, "全栈开发") || !strings.Contains(lg, "blog.example.com") {
		t.Fatalf("lg lost intro or links")
	}
}

func TestRenderCardThemes(t *testing.T) {
	data := cardData{Nickname: "张三"}
	auto := renderForTest(t, SizeMD, ThemeAuto, data)
	light := renderForTest(t, SizeMD, ThemeLight, data)
	dark := renderForTest(t, SizeMD, ThemeDark, data)

	if !strings.Contains(auto, "prefers-color-scheme: dark") {
		t.Fatalf("auto theme missing the dark media query")
	}
	if strings.Contains(auto, lightPalette.Background) == false {
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
	svg := renderForTest(t, SizeMD, ThemeLight, data)
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

func TestHostOf(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://blog.example.com/post/1", "blog.example.com"},
		{"http://github.com/alice", "github.com"},
		{"github.com/alice", "github.com"},
		{"not a url", "not a url"},
	}
	for _, c := range cases {
		if got := hostOf(c.in); got != c.want {
			t.Fatalf("hostOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRenderUnknownKeyAnswersErrorCard(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{}}
	service := newTestService(users, newFakeBadgeRepository(), &fakeAuditRepository{})

	result, err := service.Render(context.Background(), RenderInput{Key: "unknown", Size: "md", Theme: "auto"})
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

	result, err := service.Render(context.Background(), RenderInput{Key: "render-key", Size: "lg", Theme: "dark"})
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

	first, err := service.Render(context.Background(), RenderInput{Key: "cache-key", Size: "md", Theme: "auto"})
	if err != nil {
		t.Fatalf("first Render error = %v", err)
	}
	second, err := service.Render(context.Background(), RenderInput{Key: "cache-key", Size: "md", Theme: "auto"})
	if err != nil {
		t.Fatalf("second Render error = %v", err)
	}
	if string(first.SVG) != string(second.SVG) || first.ETag != second.ETag {
		t.Fatalf("cached render diverged")
	}

	// A different variant must not collide with the cached one.
	other, err := service.Render(context.Background(), RenderInput{Key: "cache-key", Size: "lg", Theme: "auto"})
	if err != nil {
		t.Fatalf("variant Render error = %v", err)
	}
	if string(other.SVG) == string(first.SVG) {
		t.Fatalf("size variant collided with the cached md render")
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

func TestRenderInvalidParamsFallBackToDefaults(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: {Nickname: strPtr("张三")}}}
	badges := newFakeBadgeRepository()
	if err := badges.Create(context.Background(), &model.Badge{UserID: 7, BadgeKey: "fallback-key"}); err != nil {
		t.Fatalf("seed badge error = %v", err)
	}
	service := newTestService(users, badges, &fakeAuditRepository{})

	// Nonsense size/theme fall back to md/auto rather than erroring: an img
	// embed cannot show an error envelope to its viewer.
	result, err := service.Render(context.Background(), RenderInput{Key: "fallback-key", Size: "xxl", Theme: "neon"})
	if err != nil {
		t.Fatalf("Render error = %v", err)
	}
	if result.NotFound || !strings.Contains(string(result.SVG), `width="460"`) {
		t.Fatalf("fallback render = %s", result.SVG)
	}
	if !strings.Contains(string(result.SVG), "prefers-color-scheme") {
		t.Fatalf("fallback theme should be auto")
	}
}

func TestDisablePurgesRenderCache(t *testing.T) {
	users := &fakeUserRepository{cards: map[int64]*repository.PublicCard{7: {Nickname: strPtr("张三")}}}
	badges := newFakeBadgeRepository()
	if err := badges.Create(context.Background(), &model.Badge{UserID: 7, BadgeKey: "purge-key"}); err != nil {
		t.Fatalf("seed badge error = %v", err)
	}
	service := newTestService(users, badges, &fakeAuditRepository{})

	// Warm the cache with two variants.
	for _, variant := range []RenderInput{
		{Key: "purge-key", Size: "md", Theme: "auto"},
		{Key: "purge-key", Size: "lg", Theme: "dark"},
	} {
		if _, err := service.Render(context.Background(), variant); err != nil {
			t.Fatalf("warm render error = %v", err)
		}
	}

	if err := service.Disable(context.Background(), DisableInput{UserID: 7}); err != nil {
		t.Fatalf("Disable error = %v", err)
	}

	// Both variants must now answer the not-found card — the cache no longer
	// serves the pre-disable render.
	for _, variant := range []RenderInput{
		{Key: "purge-key", Size: "md", Theme: "auto"},
		{Key: "purge-key", Size: "lg", Theme: "dark"},
	} {
		result, err := service.Render(context.Background(), variant)
		if err != nil {
			t.Fatalf("post-disable render error = %v", err)
		}
		if !result.NotFound {
			t.Fatalf("variant %+v served a cached render after disable", variant)
		}
	}
}

// TestRenderStartsWithXMLDeclaration pins the html/template regression: the
// whole point of the text/template switch is that the body begins with a real
// <?xml declaration — html/template escaped it to &lt;?xml, and an <img> embed
// refuses to parse a body that does not start with '<'.
func TestRenderStartsWithXMLDeclaration(t *testing.T) {
	for _, size := range []Size{SizeSM, SizeMD, SizeLG} {
		svg, err := renderCard(size, ThemeLight, cardData{Nickname: "张三"})
		if err != nil {
			t.Fatalf("render %s: %v", size, err)
		}
		if !strings.HasPrefix(string(svg), `<?xml version="1.0" encoding="UTF-8"?>`) {
			t.Fatalf("%s body does not start with the XML declaration: %q", size, svg[:40])
		}
	}
	if body := string(renderErrorCard()); !strings.HasPrefix(body, `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Fatalf("error card does not start with the XML declaration: %q", body[:40])
	}
}

func TestRenderCardLinksToMembersOwnPage(t *testing.T) {
	// Blog wins when both exist.
	withBoth := cardData{Nickname: "张三", LinkTarget: "https://blog.example.com"}
	svg := renderForTest(t, SizeMD, ThemeLight, withBoth)
	if !strings.Contains(svg, `<a href="https://blog.example.com" target="_blank" rel="noopener noreferrer">`) {
		t.Fatalf("card missing the link wrap: %s", svg[:200])
	}
	if !strings.Contains(svg, "</a>") {
		t.Fatalf("card link never closes")
	}

	// No target, no link element at all.
	without := renderForTest(t, SizeMD, ThemeLight, cardData{Nickname: "张三"})
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

// TestRenderBorderStaysInsideCanvas pins the missing-right-border regression:
// the hairline rect starts at x=0.5, so its width must be canvas-1 — a full
// width pushes the right stroke outside the viewBox and the browser clips it.
func TestRenderBorderStaysInsideCanvas(t *testing.T) {
	for size, want := range map[Size][2]int{
		SizeSM: {320, 72},
		SizeMD: {460, 120},
		SizeLG: {540, 200},
	} {
		svg := renderForTest(t, size, ThemeLight, cardData{Nickname: "张三"})
		wantBorder := `x="0.5" y="0.5" width="` + strconv.Itoa(want[0]-1) +
			`" fill="none" stroke="#e5e7eb" height="` + strconv.Itoa(want[1]-1) + `"`
		if !strings.Contains(svg, wantBorder) {
			t.Fatalf("%s border rect not found as %q", size, wantBorder)
		}
	}
}
