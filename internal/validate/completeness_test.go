package validate_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

var blankCases = []struct {
	name  string
	value string
	blank bool
}{
	{"empty", "", true}, {"ascii spaces", "   ", true}, {"tab", "\t", true},
	{"newline", "\n", true}, {"NBSP", "\u00a0", true}, {"ideographic space", "\u3000", true},
	{"zero width", "\u200b", false}, {"real name", "张三", false}, {"padded", "  张三  ", false},
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

func TestIncompleteProfileFields(t *testing.T) {
	tests := []struct {
		name                                              string
		userName, phoneNumber, qqNumber, major, studentID string
		want                                              []string
	}{
		{"clean account reports nothing", "张三", "13800000000", "10001", "软件工程", "B24040001", nil},
		{"fully dirty import row", "B24040525", "", "", "", "B24040525", []string{"name", "phone_number", "qq_number", "major"}},
		{"real name but blank contact fields", "李四", "", "", "", "B24040002", []string{"phone_number", "qq_number", "major"}},
		{"case-insensitive student ID placeholder", "b24040003", "13800000003", "10003", "通信工程", "B24040003", []string{"name"}},
		{"student ID with surrounding space", " B24040006 ", "13800000006", "10006", "软件工程", "B24040006", []string{"name"}},
		{"NBSP-only name counts as blank", "\u00a0", "13800000005", "10005", "软件工程", "B24040005", []string{"name"}},
		{"control character in name is reported", "张三\x01", "13800000008", "10008", "软件工程", "B24040008", []string{"name"}},
		{"control character in phone is reported", "王五", "13800000009\x1f", "10009", "软件工程", "B24040009", []string{"phone_number"}},
		{"control character in major is reported", "王五", "13800000010", "10010", "软\u009f件工程", "B24040010", []string{"major"}},
		{"over-long name is reported", strings.Repeat("名", validate.MaxNameLength+1), "13800000011", "10011", "软件工程", "B24040011", []string{"name"}},
		{"latin name is reported", "John", "13800000016", "10016", "软件工程", "B24040016", []string{"name"}},
		{"zero-width name is reported", "\u200b张三", "13800000017", "10017", "软件工程", "B24040017", []string{"name"}},
		{"interpunct name is complete", "张·三", "13800000018", "10018", "软件工程", "B24040018", nil},
		{"blank qq_number alone is reported", "王五", "13800000007", "", "软件工程", "B24040007", []string{"qq_number"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := validate.IncompleteProfileFields(test.userName, test.phoneNumber, test.qqNumber, test.major, test.studentID)
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("IncompleteProfileFields() = %v, want %v", got, test.want)
			}
		})
	}
}
