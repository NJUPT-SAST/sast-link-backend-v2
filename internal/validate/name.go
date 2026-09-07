package validate

import "strings"

// The name rule, product-level: the only accepted characters are Han and the
// interpunct (and its common variants). This is a deliberate port of the
// frontend's realNameSchema (lib/validations/name.ts, 民委发〔2016〕33号文
// alignment — Chinese-name-only for the NJUPT student context); the frontend
// enforces it on every form that collects a name, and the backend now mirrors
// it in the completion rule and on every write path so a value the product
// refuses can never hide from the completion prompt.
//
// The frontend spells the set as /^[\p{Script=Han}\u00B7\u30FB\uFF65\u2027\u0387]+$/.
// PostgreSQL's regex engine has no \p{Script=...} support, so the SQL half
// (V016's sl_name_invalid) spells the ranges out literally, and this Go half
// must match the SQL list exactly — TestNameRuleMatchesSQL feeds both the same
// inputs. The blocks below take the superscript strategy: they cover every
// Han block through Unicode 16 (including Extension I), so a character newer
// than the browser's Unicode tables may pass here while the frontend still
// refuses it — a refusal the user can clear. The dangerous drift is the other
// direction: a Han character the frontend accepts but the backend flags would
// leave a prompt the user cannot clear.

var nameRanges = []struct{ lo, hi rune }{
	// CJK Unified Ideographs Extension A
	{0x3400, 0x4dbf},
	// CJK Unified Ideographs
	{0x4e00, 0x9fff},
	// CJK Compatibility Ideographs
	{0xf900, 0xfaff},
	// Extension B
	{0x20000, 0x2a6df},
	// Extension C
	{0x2a700, 0x2b73f},
	// Extension D
	{0x2b740, 0x2b81f},
	// Extension E
	{0x2b820, 0x2ceaf},
	// Extension F
	{0x2ceb0, 0x2ebef},
	// Extension I (Unicode 16)
	{0x2ebf0, 0x2ee5f},
	// CJK Compatibility Ideographs Supplement
	{0x2f800, 0x2fa1f},
	// Extension G
	{0x30000, 0x3134f},
	// Extension H
	{0x31350, 0x323af},
	// Interpunct U+00B7 and the common variants the frontend normalizes to it
	{0x00b7, 0x00b7},
	{0x2027, 0x2027},
	{0x0387, 0x0387},
	{0x30fb, 0x30fb},
	{0xff65, 0xff65},
}

func inNameRanges(symbol rune) bool {
	for _, block := range nameRanges {
		if symbol >= block.lo && symbol <= block.hi {
			return true
		}
	}
	return false
}

// IsInvalidName reports whether value is blank or holds any character outside
// the name rule's set (Han blocks as enumerated in nameRanges, plus the
// interpunct variants). Control characters and invisible codepoints are refused
// by it — the set is a whitelist, not a list of bad shapes.
//
// This is the Go half of V016's sl_name_invalid; keep the two in lockstep, with
// TestNameRuleMatchesSQL feeding both the same inputs. Length is deliberately
// not part of this predicate — the width checks own that shape.
func IsInvalidName(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return true
	}
	for _, symbol := range trimmed {
		if !inNameRanges(symbol) {
			return true
		}
	}
	return false
}
