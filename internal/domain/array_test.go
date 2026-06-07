package domain

import (
	"reflect"
	"testing"
)

func TestStringArrayValue(t *testing.T) {
	cases := []struct {
		name string
		in   StringArray
		want any
	}{
		{
			name: "nil",
			in:   nil,
			want: nil,
		},
		{
			name: "empty",
			in:   StringArray{},
			want: "{}",
		},
		{
			name: "values",
			in:   StringArray{"openid", "profile"},
			want: "{\"openid\",\"profile\"}",
		},
		{
			name: "escaped",
			in:   StringArray{"quote\"me", `back\slash`},
			want: "{\"quote\\\"me\",\"back\\\\slash\"}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.in.Value()
			if err != nil {
				t.Fatalf("Value() error = %v", err)
			}
			if got != c.want {
				t.Fatalf("Value() = %#v, want %#v", got, c.want)
			}
		})
	}
}

func TestStringArrayScan(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want StringArray
	}{
		{
			name: "nil",
			in:   nil,
			want: nil,
		},
		{
			name: "empty",
			in:   "{}",
			want: StringArray{},
		},
		{
			name: "unquoted",
			in:   "{openid,profile}",
			want: StringArray{"openid", "profile"},
		},
		{
			name: "quoted byte slice",
			in:   []byte(`{"openid profile","email"}`),
			want: StringArray{"openid profile", "email"},
		},
		{
			name: "escaped",
			in:   `{"quote\"me","back\\slash"}`,
			want: StringArray{"quote\"me", `back\slash`},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got StringArray
			if err := got.Scan(c.in); err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Scan() = %#v, want %#v", got, c.want)
			}
		})
	}
}

func TestStringArrayScanInvalid(t *testing.T) {
	cases := []any{
		123,
		"not-array",
		`{"unterminated}`,
	}

	for _, c := range cases {
		t.Run("invalid", func(t *testing.T) {
			var got StringArray
			if err := got.Scan(c); err == nil {
				t.Fatalf("Scan(%#v) error = nil", c)
			}
		})
	}
}
