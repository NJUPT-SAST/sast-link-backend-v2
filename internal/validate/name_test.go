package validate_test

import (
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// The name rule is a whitelist: Han blocks plus the interpunct variants the
// frontend normalizes to U+00B7. Control characters, latin letters, digits,
// whitespace and invisible codepoints are all outside it, so IsInvalidName
// reports them without needing the shape checks. The SQL half lives in
// V016's sl_name_invalid; TestNameRuleMatchesSQL feeds both the same inputs.
func TestIsInvalidName(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "basic Han", value: "张三", want: false},
		{name: "Han with interpunct", value: "张·三", want: false},
		{name: "interpunct variants (normalized on submit, may exist in data)", value: "张・三", want: false},
		{name: "Extension B Han", value: "\U00020bb7", want: false},
		{name: "single Han", value: "张", want: false},
		{name: "padded name", value: "  张三  ", want: false},
		{name: "blank", value: "", want: true},
		{name: "whitespace only", value: "   ", want: true},
		{name: "latin name", value: "AAA", want: true},
		{name: "english name", value: "John", want: true},
		{name: "digits", value: "B24040525", want: true},
		{name: "student-id placeholder", value: "B24040525", want: true},
		{name: "embedded control character", value: "张\x01三", want: true},
		{name: "zero-width space", value: "张\u200b三", want: true},
		{name: "NBSP", value: "\u00a0", want: true},
		{name: "full-width space U+3000 is not Han", value: "张\u3000三", want: true},
		{name: "emoji", value: "张😀", want: true},
		{name: "hyphen is not an interpunct", value: "张-三", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validate.IsInvalidName(test.value); got != test.want {
				t.Errorf("IsInvalidName(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}
