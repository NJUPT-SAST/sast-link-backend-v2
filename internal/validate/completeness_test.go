package validate_test

import (
	"reflect"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// blankCases are the values whose blankness SQL and Go have to agree on. The
// interesting ones are the invisible codepoints: PostgreSQL's one-argument
// btrim() strips ASCII spaces only, so a naive `btrim(name) = ”` in V010 would
// call a name holding a single NBSP complete while PUT /user/profile refuses
// every edit to it. The account would be told it is fine and still be unable to
// submit anything.
//
// Zero-width codepoints are deliberately NOT blank on either side: they are not
// whitespace, and validate.HasControlCharacter is what rejects them on input.
var blankCases = []struct {
	name  string
	value string
	blank bool
}{
	{name: "empty", value: "", blank: true},
	{name: "ascii spaces", value: "   ", blank: true},
	{name: "tab", value: "\t", blank: true},
	{name: "newline", value: "\n", blank: true},
	{name: "carriage return", value: "\r", blank: true},
	{name: "vertical tab", value: "\v", blank: true},
	{name: "form feed", value: "\f", blank: true},
	{name: "NEL U+0085", value: "\u0085", blank: true},
	{name: "NBSP U+00A0", value: "\u00a0", blank: true},
	{name: "ogham space U+1680", value: "\u1680", blank: true},
	{name: "en quad U+2000", value: "\u2000", blank: true},
	{name: "em space U+2003", value: "\u2003", blank: true},
	{name: "line separator U+2028", value: "\u2028", blank: true},
	{name: "paragraph separator U+2029", value: "\u2029", blank: true},
	{name: "narrow NBSP U+202F", value: "\u202f", blank: true},
	{name: "medium mathematical space U+205F", value: "\u205f", blank: true},
	{name: "ideographic space U+3000", value: "\u3000", blank: true},
	{name: "mixed whitespace", value: " \t\u00a0\u3000 ", blank: true},
	{name: "zero-width space U+200B is not blank", value: "\u200b", blank: false},
	{name: "zero-width non-joiner U+200C is not blank", value: "\u200c", blank: false},
	{name: "BOM U+FEFF is not blank", value: "\ufeff", blank: false},
	{name: "real name", value: "张三", blank: false},
	{name: "padded real name", value: "  张三  ", blank: false},
}

func TestIsBlank(t *testing.T) {
	for _, test := range blankCases {
		t.Run(test.name, func(t *testing.T) {
			if got := validate.IsBlank(test.value); got != test.blank {
				t.Errorf("IsBlank(%q) = %t, want %t", test.value, got, test.blank)
			}
		})
	}
}

// The four shapes below are the ones the production import actually produced,
// measured against a dump of the legacy database: a fully dirty row (blank
// phone/major plus name filled in with the student ID), a row whose name is real
// but whose phone/major are blank, a row where only the name is wrong, and a
// clean row.
func TestIncompleteProfileFields(t *testing.T) {
	tests := []struct {
		name        string
		userName    string
		phoneNumber string
		major       string
		studentID   string
		want        []string
	}{
		{
			name: "clean account reports nothing", userName: "张三",
			phoneNumber: "13800000000", major: "软件工程", studentID: "B24040001",
			want: nil,
		},
		{
			name: "fully dirty import row", userName: "B24040525",
			phoneNumber: "", major: "", studentID: "B24040525",
			want: []string{"name", "phone_number", "major"},
		},
		{
			name: "real name but blank contact fields", userName: "李四",
			phoneNumber: "", major: "", studentID: "B24040002",
			want: []string{"phone_number", "major"},
		},
		{
			name: "only the name is a student ID", userName: "B24040003",
			phoneNumber: "13800000003", major: "通信工程", studentID: "B24040003",
			want: []string{"name"},
		},
		{
			// The import produced both cases. A case-sensitive comparison would
			// pass this row and leave the placeholder in place.
			name: "lowercase name matches uppercase student ID", userName: "b24042022",
			phoneNumber: "13800000004", major: "软件工程", studentID: "B24042022",
			want: []string{"name"},
		},
		{
			name: "name is student ID with surrounding space", userName: " B24040006 ",
			phoneNumber: "13800000006", major: "软件工程", studentID: "B24040006",
			want: []string{"name"},
		},
		{
			name: "NBSP-only name counts as blank", userName: "\u00a0",
			phoneNumber: "13800000005", major: "软件工程", studentID: "B24040005",
			want: []string{"name"},
		},
		{
			// qq_number is absent from the signature on purpose: it is empty for
			// every imported account, so reporting it would flag the whole table
			// forever. This case documents that a row missing only that field is
			// reported as complete.
			name: "blank qq_number is not reported", userName: "王五",
			phoneNumber: "13800000007", major: "软件工程", studentID: "B24040007",
			want: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := validate.IncompleteProfileFields(test.userName, test.phoneNumber, test.major, test.studentID)
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("IncompleteProfileFields() = %v, want %v", got, test.want)
			}
		})
	}
}
