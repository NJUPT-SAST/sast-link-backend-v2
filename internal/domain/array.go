package domain

import (
	"database/sql/driver"
	"fmt"
	"strings"
)

// StringArray maps PostgreSQL text[] columns without pulling in an extra driver package.
type StringArray []string

// Value implements driver.Valuer.
func (a StringArray) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}

	items := make([]string, len(a))
	for i, item := range a {
		items[i] = quotePostgresArrayElement(item)
	}
	return "{" + strings.Join(items, ",") + "}", nil
}

// Scan implements sql.Scanner.
func (a *StringArray) Scan(src any) error {
	if src == nil {
		*a = nil
		return nil
	}

	switch v := src.(type) {
	case string:
		return a.scanString(v)
	case []byte:
		return a.scanString(string(v))
	default:
		return fmt.Errorf("scan StringArray: unsupported source type %T", src)
	}
}

func (a *StringArray) scanString(src string) error {
	if src == "{}" {
		*a = StringArray{}
		return nil
	}
	if len(src) < 2 || src[0] != '{' || src[len(src)-1] != '}' {
		return fmt.Errorf("scan StringArray: invalid postgres array %q", src)
	}

	items := make([]string, 0)
	var item strings.Builder
	inQuotes := false
	escaped := false
	quoted := false

	flush := func() error {
		value := item.String()
		if !quoted && strings.EqualFold(value, "NULL") {
			return fmt.Errorf("scan StringArray: NULL array element is not supported in %q", src)
		}
		items = append(items, value)
		item.Reset()
		quoted = false
		return nil
	}

	for _, r := range src[1 : len(src)-1] {
		if escaped {
			item.WriteRune(r)
			escaped = false
			continue
		}

		if inQuotes {
			switch r {
			case '\\':
				escaped = true
			case '"':
				inQuotes = false
			default:
				item.WriteRune(r)
			}
			continue
		}

		switch r {
		case '"':
			inQuotes = true
			quoted = true
		case ',':
			if err := flush(); err != nil {
				return err
			}
		default:
			item.WriteRune(r)
		}
	}

	if escaped || inQuotes {
		return fmt.Errorf("scan StringArray: unterminated quoted element in %q", src)
	}
	if err := flush(); err != nil {
		return err
	}

	*a = StringArray(items)
	return nil
}

func quotePostgresArrayElement(item string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range item {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}
