package badge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"strings"
)

// Size identifies one badge canvas. Every badge of a given size renders at
// exactly the same dimensions regardless of content — empty fields leave
// their slot blank rather than reflowing the layout, so friend-link walls
// stay a uniform grid.
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

// layout carries every per-size geometry and truncation bound the template
// consumes. Fixed canvas, fixed slots.
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

	DeptX    int
	DeptY    int
	DeptSize int
	DeptMax  int

	IntroX    int
	IntroY    int
	IntroSize int
	IntroMax  int

	LinksX    int
	LinksY    int
	LinksSize int
	LinksMax  int

	BrandX    int
	BrandY    int
	BrandSize int
}

// layouts pins the three canvases. All Y values are text baselines.
var layouts = map[Size]layout{
	SizeSM: {
		Width: 320, Height: 72,
		AvatarX: 8, AvatarY: 8, AvatarSize: 56, AvatarRadius: 28,
		NameX: 78, NameY: 34, NameSize: 17, NameMax: 12,
		DeptX: 78, DeptY: 56, DeptSize: 11, DeptMax: 18,
		BrandX: 312, BrandY: 18, BrandSize: 9,
	},
	SizeMD: {
		Width: 460, Height: 120,
		AvatarX: 16, AvatarY: 16, AvatarSize: 88, AvatarRadius: 44,
		NameX: 122, NameY: 52, NameSize: 20, NameMax: 14,
		DeptX: 122, DeptY: 76, DeptSize: 12, DeptMax: 24,
		IntroX: 122, IntroY: 98, IntroSize: 12, IntroMax: 26,
		// md renders no links row: only lg has the slot (see renderCard).
		LinksX: 0, LinksY: 0, LinksSize: 0, LinksMax: 0,
		BrandX: 448, BrandY: 18, BrandSize: 9,
	},
	SizeLG: {
		Width: 540, Height: 200,
		AvatarX: 28, AvatarY: 36, AvatarSize: 128, AvatarRadius: 64,
		NameX: 180, NameY: 88, NameSize: 24, NameMax: 16,
		DeptX: 180, DeptY: 118, DeptSize: 14, DeptMax: 28,
		IntroX: 180, IntroY: 148, IntroSize: 14, IntroMax: 34,
		LinksX: 180, LinksY: 178, LinksSize: 12, LinksMax: 44,
		BrandX: 526, BrandY: 20, BrandSize: 9,
	},
}

// palette is one resolved color set.
type palette struct {
	Background string
	Foreground string
	Muted      string
	Hairline   string
	Accent     string
}

var lightPalette = palette{
	Background: "#ffffff",
	Foreground: "#1c1f23",
	Muted:      "#6b7280",
	Hairline:   "#e5e7eb",
	Accent:     "#0a96d6",
}

var darkPalette = palette{
	Background: "#16181d",
	Foreground: "#e8eaed",
	Muted:      "#9aa0a6",
	Hairline:   "#2a2d33",
	Accent:     "#4db8f0",
}

// departmentLabels maps the department enum to its Chinese display name,
// aligned with the frontend constants (lib/constants/admin.ts).
var departmentLabels = map[string]string{
	"software": "软件研发部",
	"media":    "多媒体部",
}

// departmentLabel resolves a department value to its display name, falling
// back to the raw value so an unknown enum never renders empty.
func departmentLabel(value string) string {
	if label, ok := departmentLabels[value]; ok {
		return label
	}
	return value
}

// cardData is the resolved, truncated, display-ready projection of one badge.
type cardData struct {
	AvatarDataURI string // empty → placeholder mark
	AvatarInitial string // first rune of the nickname, for the fallback
	Nickname      string
	Department    string
	Intro         string
	Links         string
	Brand         string
}

// svgTemplate renders one badge. The palette rides in through classes so the
// auto theme can carry both palettes behind a media query; fixed themes emit
// only theirs.
var svgTemplate = template.Must(template.New("badge").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{{.Layout.Width}}" height="{{.Layout.Height}}" viewBox="0 0 {{.Layout.Width}} {{.Layout.Height}}" role="img" aria-label="{{.Data.Nickname}} 的 SAST Link 徽标">
<style>
.card-bg{fill:{{.Palette.Background}}}.card-fg{fill:{{.Palette.Foreground}}}.card-muted{fill:{{.Palette.Muted}}}.card-accent{fill:{{.Palette.Accent}}}
{{if .AutoTheme}}@media (prefers-color-scheme: dark){.card-bg{fill:{{.Dark.Background}}}.card-fg{fill:{{.Dark.Foreground}}}.card-muted{fill:{{.Dark.Muted}}}.card-accent{fill:{{.Dark.Accent}}}}
{{end}}</style><rect class="card-bg" width="{{.Layout.Width}}" height="{{.Layout.Height}}" rx="10"/>
<rect x="0.5" y="0.5" width="{{.Layout.Width}}" fill="none" stroke="{{.Palette.Hairline}}" height="{{.DecHeight}}" rx="10" stroke-width="1"/>
{{if .Data.AvatarDataURI}}<image x="{{.Layout.AvatarX}}" y="{{.Layout.AvatarY}}" width="{{.Layout.AvatarSize}}" height="{{.Layout.AvatarSize}}" href="{{.Data.AvatarDataURI}}" clip-path="inset(0 round {{.Layout.AvatarRadius}}px)" preserveAspectRatio="xMidYMid slice"/>
{{else if .Data.AvatarInitial}}<circle cx="{{.DecAvatarCX}}" cy="{{.DecAvatarCY}}" r="{{.Layout.AvatarRadius}}" class="card-muted"/>
<text x="{{.DecAvatarCX}}" y="{{.DecAvatarTextY}}" text-anchor="middle" class="card-bg" font-size="{{.DecAvatarFontSize}}" font-family="{{.FontStack}}" font-weight="600">{{.Data.AvatarInitial}}</text>
{{else}}<circle cx="{{.DecAvatarCX}}" cy="{{.DecAvatarCY}}" r="{{.Layout.AvatarRadius}}" class="card-bg" stroke="{{.Palette.Hairline}}" stroke-width="1"/>
<circle cx="{{.DecAvatarCX}}" cy="{{.DecAvatarCY}}" r="{{.DecAvatarRadiusInner}}" class="card-accent" fill-opacity="0.25"/>
{{end}}<text x="{{.Layout.NameX}}" y="{{.Layout.NameY}}" class="card-fg" font-size="{{.Layout.NameSize}}" font-family="{{.FontStack}}" font-weight="600">{{.Data.Nickname}}</text>
{{if .Data.Department}}<text x="{{.Layout.DeptX}}" y="{{.Layout.DeptY}}" class="card-muted" font-size="{{.Layout.DeptSize}}" font-family="{{.FontStack}}">{{.Data.Department}}</text>
{{end}}{{if .Data.Intro}}<text x="{{.Layout.IntroX}}" y="{{.Layout.IntroY}}" class="card-muted" font-size="{{.Layout.IntroSize}}" font-family="{{.FontStack}}">{{.Data.Intro}}</text>
{{end}}{{if .Data.Links}}<text x="{{.Layout.LinksX}}" y="{{.Layout.LinksY}}" class="card-accent" font-size="{{.Layout.LinksSize}}" font-family="{{.FontStack}}">{{.Data.Links}}</text>
{{end}}<text x="{{.Layout.BrandX}}" y="{{.Layout.BrandY}}" text-anchor="end" class="card-muted" font-size="{{.Layout.BrandSize}}" font-family="{{.FontStack}}" letter-spacing="1">SAST Link</text>
</svg>
`))

// fontStack is the shared CJK-capable family list. GitHub's camo proxy strips
// external resource references, so fonts must come from the viewer's system;
// the stack covers the three mainstream platforms and accepts the minor
// cross-platform rendering differences.
const fontStack = `'PingFang SC','Microsoft YaHei','Noto Sans CJK SC','Source Han Sans SC',sans-serif`

// renderCard renders one badge SVG. It never fails on content: truncation
// bounds every field and missing fields simply skip their slot.
func renderCard(size Size, theme Theme, data cardData) ([]byte, error) {
	chosen, ok := layouts[size]
	if !ok {
		return nil, fmt.Errorf("render badge: unknown size %q", size)
	}

	// Field visibility is size-driven: sm is name+department only, md adds
	// the intro, lg adds the social links. Empty fields already skip their
	// slot; this clamp also hides fields a smaller canvas has no slot for.
	if size == SizeSM {
		data.Intro = ""
		data.Links = ""
	}
	if size == SizeMD {
		data.Links = ""
	}

	view := struct {
		Layout               layout
		Palette              palette
		Dark                 palette
		AutoTheme            bool
		Data                 cardData
		FontStack            string
		DecHeight            int
		DecAvatarCX          int
		DecAvatarCY          int
		DecAvatarTextY       int
		DecAvatarFontSize    int
		DecAvatarRadiusInner int
	}{
		Layout:    chosen,
		Palette:   lightPalette,
		Dark:      darkPalette,
		AutoTheme: theme == ThemeAuto,
		Data:      data,
		FontStack: fontStack,
		DecHeight: chosen.Height - 1,
	}
	switch theme {
	case ThemeDark:
		view.Palette = darkPalette
	case ThemeAuto, ThemeLight:
		view.Palette = lightPalette
	default:
		return nil, fmt.Errorf("render badge: unknown theme %q", theme)
	}

	view.DecAvatarCX = chosen.AvatarX + chosen.AvatarRadius
	view.DecAvatarCY = chosen.AvatarY + chosen.AvatarRadius
	// The initial glyph sits on the circle's optical center: baseline ≈ cy + 35% of the radius.
	view.DecAvatarTextY = view.DecAvatarCY + chosen.AvatarRadius*7/20
	view.DecAvatarFontSize = chosen.AvatarRadius
	view.DecAvatarRadiusInner = chosen.AvatarRadius / 2

	var buf bytes.Buffer
	if err := svgTemplate.Execute(&buf, view); err != nil {
		return nil, fmt.Errorf("render badge: execute template: %w", err)
	}
	return buf.Bytes(), nil
}

// errorCardSVG is the 404 body: an img embed must not crack, so an unknown
// key renders a neutral card instead of a JSON envelope.
var errorCardSVG = template.Must(template.New("badge-error").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="460" height="120" viewBox="0 0 460 120" role="img" aria-label="徽标不存在">
<rect width="460" height="120" rx="10" fill="#ffffff"/>
<rect x="0.5" y="0.5" width="459" height="119" rx="10" fill="none" stroke="#e5e7eb" stroke-width="1"/>
<circle cx="64" cy="60" r="28" fill="none" stroke="#e5e7eb" stroke-width="1.5"/>
<path d="M 54 50 L 74 70 M 74 50 L 54 70" stroke="#6b7280" stroke-width="2" stroke-linecap="round"/>
<text x="110" y="66" font-size="16" font-family="{{.FontStack}}" fill="#6b7280">徽标不存在或已关闭</text>
<text x="448" y="18" text-anchor="end" font-size="9" font-family="{{.FontStack}}" fill="#6b7280" letter-spacing="1">SAST Link</text>
</svg>
`))

// renderErrorCard renders the not-found card.
func renderErrorCard() []byte {
	var buf bytes.Buffer
	if err := errorCardSVG.Execute(&buf, map[string]string{"FontStack": fontStack}); err != nil {
		// A template this static cannot fail; fall back to a minimal body so
		// the endpoint still answers image/svg+xml.
		return []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="460" height="120"></svg>`)
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

// hostOf extracts a URL's host, tolerating scheme-less input; it falls back
// to the raw value so a malformed link still shows something identifiable.
func hostOf(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if idx := strings.Index(trimmed, "://"); idx >= 0 {
		trimmed = trimmed[idx+3:]
	}
	if idx := strings.IndexAny(trimmed, "/?#"); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	if trimmed == "" {
		return strings.TrimSpace(raw)
	}
	return trimmed
}

// joinLinks collapses the social hosts into one display line.
func joinLinks(links []string) string {
	return strings.Join(links, " · ")
}
