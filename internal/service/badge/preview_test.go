package badge

import (
	"os"
	"testing"
)

// TestWritePreviewFiles renders one sample card per size into the directory
// named by BADGE_PREVIEW_DIR, for manual visual inspection during development.
// Skipped unless the variable is set, so CI never writes anywhere.
func TestWritePreviewFiles(t *testing.T) {
	dir := os.Getenv("BADGE_PREVIEW_DIR")
	if dir == "" {
		t.Skip("BADGE_PREVIEW_DIR not set")
	}
	data := cardData{
		Nickname:      "张三",
		Department:    "软件研发部",
		Intro:         "Full-stack developer / 在写 Go 和 React",
		Links:         "blog.example.com · github.com/zhangsan",
		AvatarInitial: "张",
	}
	for _, size := range []Size{SizeSM, SizeMD, SizeLG} {
		for _, theme := range []Theme{ThemeAuto, ThemeLight, ThemeDark} {
			svg, err := renderCard(size, theme, data)
			if err != nil {
				t.Fatalf("render %s/%s: %v", size, theme, err)
			}
			path := dir + "/badge-" + string(size) + "-" + string(theme) + ".svg"
			if err := os.WriteFile(path, svg, 0o600); err != nil { // #nosec G703 -- dev-only preview helper, dir is operator-controlled
				t.Fatalf("write %s: %v", path, err)
			}
		}
	}
	// The not-found card too.
	if err := os.WriteFile(dir+"/badge-error.svg", renderErrorCard(), 0o600); err != nil { // #nosec G703 -- dev-only preview helper, dir is operator-controlled
		t.Fatalf("write error card: %v", err)
	}
}
