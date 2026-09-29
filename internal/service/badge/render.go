package badge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"strings"
	"text/template"
)

// Size identifies a badge canvas. Only the compact tile ships today — sm,
// 320×72 — while md and lg are reserved for a later iteration; the render
// path ignores the size parameter until then.
type Size string

const (
	SizeSM Size = "sm"
	SizeMD Size = "md"
	SizeLG Size = "lg"
)

// Theme selects the palette. Auto embeds a prefers-color-scheme media query
// so the badge follows the viewer's system (browsers switch live; GitHub's
// camo proxy needs a page refresh); light and dark pin one palette.
type Theme string

const (
	ThemeAuto  Theme = "auto"
	ThemeLight Theme = "light"
	ThemeDark  Theme = "dark"
)

// Target selects which of the member's own pages the card's click-through
// lands on. It rides the URL like theme — the embedder may override the
// member's default by hand — and unknown values normalize to the blog
// default.
type Target string

const (
	TargetBlog   Target = "blog"
	TargetGithub Target = "github"
)

// layout carries every geometry and truncation bound the template consumes.
// Fixed canvas, fixed slots. Y values are text baselines; the vertical
// divider is only drawn when its X is non-zero.
type layout struct {
	Width  int
	Height int

	AvatarX      int
	AvatarY      int
	AvatarSize   int
	AvatarRadius int

	NameX    int
	NameY    int
	NameSize int
	NameMax  int

	IntroX    int
	IntroY    int
	IntroSize int
	IntroMax  int

	DividerX  int
	DividerY1 int
	DividerY2 int

	BrandX    int
	BrandY    int
	BrandSize int
}

// compactLayout is the one badge canvas that ships today: 320×72, avatar on
// the left, nickname and quoted signature stacked on the right, brand mark
// top-right. The md and lg canvases are a later iteration.
var compactLayout = layout{
	Width: 320, Height: 72,
	AvatarX: 8, AvatarY: 8, AvatarSize: 56, AvatarRadius: 28,
	NameX: 78, NameY: 33, NameSize: 17, NameMax: 12,
	IntroX: 78, IntroY: 54, IntroSize: 11, IntroMax: 20,
	BrandX: 312, BrandY: 16, BrandSize: 9,
}

// palette is one resolved color set.
type palette struct {
	Background string
	Foreground string
	Muted      string
	Hairline   string
	Accent     string
	// Border is the outer frame's color: deliberately CONTRASTING with the
	// background rather than tonal — the light card carries a dark line and
	// the dark card a light one — so the frame stays visible on both themes
	// and on pages of either shade.
	Border string
}

var lightPalette = palette{
	Background: "#ffffff",
	Foreground: "#1c1f23",
	Muted:      "#6b7280",
	Hairline:   "#e5e7eb",
	Accent:     "#0a96d6",
	Border:     "#1c1f23",
}

var darkPalette = palette{
	Background: "#16181d",
	Foreground: "#e8eaed",
	Muted:      "#9aa0a6",
	Hairline:   "#2a2d33",
	Accent:     "#4db8f0",
	Border:     "#e8eaed",
}

// cardData is the resolved, truncated, display-ready projection of one badge.
type cardData struct {
	AvatarDataURI string // empty → placeholder mark
	AvatarInitial string // first rune of the nickname, for the fallback
	Nickname      string
	Intro         string
	Brand         string
	// LinkTarget is the member's own page the whole card links to — blog
	// first, GitHub as the fallback, empty when neither exists. An <img>
	// embed ignores links inside the SVG (camo strips them anyway); the
	// target matters where the SVG is inlined or shown via <object>, and the
	// frontend preview builds its own <a> from the same rule.
	LinkTarget string
}

// svgTemplate renders one badge. The palette rides in through classes so the
// auto theme can carry both palettes behind a media query; fixed themes emit
// only theirs.
var svgTemplate = template.Must(template.New("badge").Funcs(template.FuncMap{
	// esc escapes user-provided text for XML character data and attribute
	// contexts. text/template performs no contextual escaping — the switch from
	// html/template is deliberate: the latter escapes the XML declaration to
	// &lt;?xml, and an <img> embed refuses to parse a body that does not start
	// with a real '<'.
	"esc": html.EscapeString,
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{{.Layout.Width}}" height="{{.Layout.Height}}" viewBox="0 0 {{.Layout.Width}} {{.Layout.Height}}" role="img" aria-label="{{esc .Data.Nickname}} 的 SAST Link 徽标">
<style>
.card-bg{fill:{{.Palette.Background}}}.card-fg{fill:{{.Palette.Foreground}}}.card-muted{fill:{{.Palette.Muted}}}.card-accent{fill:{{.Palette.Accent}}}.card-line{stroke:{{.Palette.Hairline}}}.card-border{stroke:{{.Palette.Border}}}
{{if .AutoTheme}}@media (prefers-color-scheme: dark){.card-bg{fill:{{.Dark.Background}}}.card-fg{fill:{{.Dark.Foreground}}}.card-muted{fill:{{.Dark.Muted}}}.card-accent{fill:{{.Dark.Accent}}}.card-line{stroke:{{.Dark.Hairline}}}.card-border{stroke:{{.Dark.Border}}}}
{{end}}</style>{{if .Data.LinkTarget}}<a href="{{esc .Data.LinkTarget}}" target="_blank" rel="noopener noreferrer">{{end}}<rect class="card-bg" width="{{.Layout.Width}}" height="{{.Layout.Height}}" rx="10"/>
<rect x="0.5" y="0.5" width="{{.DecWidth}}" fill="none" class="card-border" height="{{.DecHeight}}" rx="10" stroke-width="1"/>
{{if .Data.AvatarDataURI}}<image x="{{.Layout.AvatarX}}" y="{{.Layout.AvatarY}}" width="{{.Layout.AvatarSize}}" height="{{.Layout.AvatarSize}}" href="{{.Data.AvatarDataURI}}" clip-path="inset(0 round {{.Layout.AvatarRadius}}px)" preserveAspectRatio="xMidYMid slice"/>
{{else if .Data.AvatarInitial}}<circle cx="{{.DecAvatarCX}}" cy="{{.DecAvatarCY}}" r="{{.Layout.AvatarRadius}}" class="card-muted"/>
<text x="{{.DecAvatarCX}}" y="{{.DecAvatarTextY}}" text-anchor="middle" class="card-bg" font-size="{{.DecAvatarFontSize}}" font-family="{{.FontStack}}" font-weight="600">{{esc .Data.AvatarInitial}}</text>
{{else}}<circle cx="{{.DecAvatarCX}}" cy="{{.DecAvatarCY}}" r="{{.Layout.AvatarRadius}}" class="card-bg card-line" stroke-width="1"/>
<circle cx="{{.DecAvatarCX}}" cy="{{.DecAvatarCY}}" r="{{.DecAvatarRadiusInner}}" class="card-accent" fill-opacity="0.25"/>
{{end}}{{if .Layout.DividerX}}<line x1="{{.Layout.DividerX}}" y1="{{.Layout.DividerY1}}" x2="{{.Layout.DividerX}}" y2="{{.Layout.DividerY2}}" class="card-line" stroke-width="1"/>
{{end}}<text x="{{.Layout.NameX}}" y="{{.Layout.NameY}}" class="card-fg" font-size="{{.Layout.NameSize}}" font-family="{{.FontStack}}" font-weight="600">{{esc .Data.Nickname}}</text>
{{if .Data.Intro}}<text x="{{.Layout.IntroX}}" y="{{.Layout.IntroY}}" class="card-muted" font-size="{{.Layout.IntroSize}}" font-family="{{.FontStack}}">「{{esc .Data.Intro}}」</text>
{{end}}<text x="{{.Layout.BrandX}}" y="{{.Layout.BrandY}}" text-anchor="end" class="card-muted" font-size="{{.Layout.BrandSize}}" font-family="{{.FontStack}}" letter-spacing="1">SAST Link</text>{{if .Data.LinkTarget}}</a>{{end}}
</svg>
`))

// fontStack is the shared CJK-capable family list. GitHub's camo proxy strips
// external resource references, so fonts must come from the viewer's system;
// the stack covers the three mainstream platforms and accepts the minor
// cross-platform rendering differences.
const fontStack = `'PingFang SC','Microsoft YaHei','Noto Sans CJK SC','Source Han Sans SC',sans-serif`

// renderCard renders one badge SVG. It never fails on content: truncation
// bounds every field and missing fields simply skip their slot.
func renderCard(theme Theme, data cardData) ([]byte, error) {
	var resolved palette
	switch theme {
	case ThemeDark:
		resolved = darkPalette
	case ThemeAuto, ThemeLight:
		resolved = lightPalette
	default:
		return nil, fmt.Errorf("render badge: unknown theme %q", theme)
	}

	view := struct {
		Layout               layout
		Palette              palette
		Dark                 palette
		AutoTheme            bool
		Data                 cardData
		FontStack            string
		DecHeight            int
		DecWidth             int
		DecAvatarCX          int
		DecAvatarCY          int
		DecAvatarTextY       int
		DecAvatarFontSize    int
		DecAvatarRadiusInner int
	}{
		Layout:    compactLayout,
		Palette:   resolved,
		Dark:      darkPalette,
		AutoTheme: theme == ThemeAuto,
		Data:      data,
		FontStack: fontStack,
		DecHeight: compactLayout.Height - 1,
		DecWidth:  compactLayout.Width - 1,
	}

	view.DecAvatarCX = compactLayout.AvatarX + compactLayout.AvatarRadius
	view.DecAvatarCY = compactLayout.AvatarY + compactLayout.AvatarRadius
	// The initial glyph sits on the circle's optical center: baseline ≈ cy + 35% of the radius.
	view.DecAvatarTextY = view.DecAvatarCY + compactLayout.AvatarRadius*7/20
	view.DecAvatarFontSize = compactLayout.AvatarRadius
	view.DecAvatarRadiusInner = compactLayout.AvatarRadius / 2

	var buf bytes.Buffer
	if err := svgTemplate.Execute(&buf, view); err != nil {
		return nil, fmt.Errorf("render badge: execute template: %w", err)
	}
	return buf.Bytes(), nil
}

// errorCardSVG is the 404 body: an img embed must not crack, so an unknown
// key renders a neutral card instead of a JSON envelope.
// errorCardSVG is the closed/unknown-key body: an img embed must not
// crack, so it renders a neutral card instead of a JSON envelope. It mirrors
// the compact card exactly — same 320×72 canvas, same class-based palette
// (theme-aware, auto carries the media query), same contrast border and the
// same avatar-slot visual language (muted circle with a bg-colored mark) —
// so a closed badge reads as "this card is off", not as a foreign object.
var errorCardSVG = template.Must(template.New("badge-error").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="320" height="72" viewBox="0 0 320 72" role="img" aria-label="徽标不存在或已关闭">
<style>
.card-bg{fill:{{.Palette.Background}}}.card-muted{fill:{{.Palette.Muted}}}.card-border{stroke:{{.Palette.Border}}}.card-mark{stroke:{{.Palette.Background}}}
{{if .AutoTheme}}@media (prefers-color-scheme: dark){.card-bg{fill:{{.Dark.Background}}}.card-muted{fill:{{.Dark.Muted}}}.card-border{stroke:{{.Dark.Border}}}.card-mark{stroke:{{.Dark.Background}}}}
{{end}}</style><rect class="card-bg" width="320" height="72" rx="10"/>
<rect x="0.5" y="0.5" width="319" height="71" rx="10" fill="none" class="card-border" stroke-width="1"/>
<circle cx="36" cy="36" r="28" class="card-muted"/>
<path d="M 26 26 L 46 46 M 46 26 L 26 46" class="card-mark" stroke-width="3" stroke-linecap="round"/>
<text x="78" y="41" class="card-muted" font-size="14" font-family="{{.FontStack}}">徽标不存在或已关闭</text>
<text x="312" y="16" text-anchor="end" class="card-muted" font-size="9" font-family="{{.FontStack}}" letter-spacing="1">SAST Link</text>
</svg>
`))

// renderErrorCard renders the not-found card in the requested theme.
func renderErrorCard(theme Theme) []byte {
	view := struct {
		Palette   palette
		Dark      palette
		AutoTheme bool
		FontStack string
	}{
		Palette:   lightPalette,
		Dark:      darkPalette,
		AutoTheme: theme == ThemeAuto,
		FontStack: fontStack,
	}
	if theme == ThemeDark {
		view.Palette = darkPalette
	}
	var buf bytes.Buffer
	if err := errorCardSVG.Execute(&buf, view); err != nil {
		// A template this static cannot fail; fall back to a minimal body so
		// the endpoint still answers image/svg+xml.
		return []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="320" height="72"></svg>`)
	}
	return buf.Bytes()
}

// truncate clamps a display string to maxChars, appending an ellipsis when
// it cut anything. Width is approximated per rune: CJK-fullwidth counts one
// slot, Latin/digits count half, so mixed strings pack predictably.
func truncate(value string, maxChars int) string {
	if maxChars <= 0 {
		return ""
	}
	slots := 0.0
	var b strings.Builder
	for _, r := range value {
		w := 1.0
		if r < 0x2E80 {
			// Latin, digits, punctuation, and spaces pack tighter.
			w = 0.55
		}
		if slots+w > float64(maxChars) {
			b.WriteRune('…')
			return b.String()
		}
		b.WriteRune(r)
		slots += w
	}
	return b.String()
}

// etag derives a strong validator from the rendered body.
func etag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:8]) + `"`
}

// firstRune returns the first printable rune of value, upper-cased, for the
// avatar fallback mark.
func firstRune(value string) string {
	for _, r := range value {
		if r > ' ' {
			return strings.ToUpper(string(r))
		}
	}
	return ""
}
