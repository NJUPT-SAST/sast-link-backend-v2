package validate_test

import (
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

func TestRequiredFieldAcceptsAndTrims(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "plain", raw: "张三", want: "张三"},
		{name: "surrounding ascii spaces", raw: "  张三  ", want: "张三"},
		{name: "interior space is kept", raw: "Zhang San", want: "Zhang San"},
		{name: "surrounding NBSP", raw: "\u00a0张三\u00a0", want: "张三"},
		{name: "at the limit", raw: strings.Repeat("字", 50), want: strings.Repeat("字", 50)},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			value, fieldErr := validate.RequiredField("name", testCase.raw, 50)
			if fieldErr != nil {
				t.Fatalf("RequiredField(%q) error = %+v, want nil", testCase.raw, fieldErr)
			}
			if value != testCase.want {
				t.Fatalf("RequiredField(%q) = %q, want %q", testCase.raw, value, testCase.want)
			}
		})
	}
}

// A whitespace-only value is ReasonRequired rather than ReasonInvalid: the rule is
// decided after trimming, so there is nothing left to call malformed. Callers map
// the two reasons onto different messages, so confusing them tells the submitter to
// remove an illegal character from a field that is simply blank.
func TestRequiredFieldRejectsWithTheRightReason(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want validate.Reason
	}{
		{name: "empty", raw: "", want: validate.ReasonRequired},
		{name: "ascii spaces only", raw: "   ", want: validate.ReasonRequired},
		{name: "NBSP only", raw: "\u00a0", want: validate.ReasonRequired},
		{name: "ideographic space only", raw: "\u3000", want: validate.ReasonRequired},
		{name: "over the limit", raw: strings.Repeat("字", 51), want: validate.ReasonTooLong},
		{name: "carriage return", raw: "张\r三", want: validate.ReasonInvalid},
		{name: "newline", raw: "张\n三", want: validate.ReasonInvalid},
		{name: "NUL", raw: "张\x00三", want: validate.ReasonInvalid},
		{name: "C1 NEL", raw: "张\u0085三", want: validate.ReasonInvalid},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			value, fieldErr := validate.RequiredField("name", testCase.raw, 50)
			if fieldErr == nil {
				t.Fatalf("RequiredField(%q) error = nil, want %s", testCase.raw, testCase.want)
			}
			if fieldErr.Reason != testCase.want {
				t.Fatalf("RequiredField(%q) reason = %s, want %s", testCase.raw, fieldErr.Reason, testCase.want)
			}
			if fieldErr.Field != "name" {
				t.Fatalf("RequiredField(%q) field = %q, want \"name\"", testCase.raw, fieldErr.Field)
			}
			// A refused value must not be handed back: a caller that stores the first
			// return without checking the second would persist a truncated or
			// control-bearing value.
			if value != "" {
				t.Fatalf("RequiredField(%q) value = %q, want empty on failure", testCase.raw, value)
			}
		})
	}
}

// Length is counted in runes because PostgreSQL counts characters. A byte-based
// check would refuse 50 Chinese characters that varchar(50) accepts.
func TestRequiredFieldCountsRunesNotBytes(t *testing.T) {
	t.Parallel()

	value, fieldErr := validate.RequiredField("major", strings.Repeat("计", 50), 50)
	if fieldErr != nil {
		t.Fatalf("RequiredField(50 multibyte runes) error = %+v, want nil", fieldErr)
	}
	if value != strings.Repeat("计", 50) {
		t.Fatalf("RequiredField() truncated the value")
	}
}

// An absent optional value is a success, not a failure. Treating "" as an error
// here is what would make department_note and note mandatory by accident.
func TestOptionalFieldAllowsAbsence(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "   ", "\u00a0", "\u3000"} {
		value, fieldErr := validate.OptionalField("note", raw, 50)
		if fieldErr != nil {
			t.Fatalf("OptionalField(%q) error = %+v, want nil", raw, fieldErr)
		}
		if value != "" {
			t.Fatalf("OptionalField(%q) = %q, want empty", raw, value)
		}
	}
}

// Present-but-bad is still refused: optional means "may be absent", not
// "unvalidated when supplied".
func TestOptionalFieldStillValidatesPresentValues(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want validate.Reason
	}{
		{name: "over the limit", raw: strings.Repeat("a", 51), want: validate.ReasonTooLong},
		{name: "control character", raw: "note\rinjected", want: validate.ReasonInvalid},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if _, fieldErr := validate.OptionalField("note", testCase.raw, 50); fieldErr == nil ||
				fieldErr.Reason != testCase.want {
				t.Fatalf("OptionalField(%q) reason = %+v, want %s", testCase.raw, fieldErr, testCase.want)
			}
		})
	}
}

// The trimming rule has to be the same one IsBlank applies, or a value this
// helper accepts could still be reported as an incomplete profile field by
// IncompleteProfileFields - the account would be told to fill in a field it
// already filled in.
func TestRequiredFieldAgreesWithIsBlank(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", " ", "\t", "\n", "\u0085", "\u00a0", "\u2028", "\u3000"} {
		_, fieldErr := validate.RequiredField("name", raw, 255)
		blank := validate.IsBlank(raw)
		if (fieldErr != nil && fieldErr.Reason == validate.ReasonRequired) != blank {
			t.Fatalf("RequiredField(%q) required=%v disagrees with IsBlank=%v", raw, fieldErr, blank)
		}
	}
}
