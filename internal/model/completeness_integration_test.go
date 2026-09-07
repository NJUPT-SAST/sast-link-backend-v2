package model_test

import (
	"fmt"
	"testing"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// V010's flag is computed by PostgreSQL, but the decision about whether a user's
// attempted fix is accepted is made in Go. If the two rules disagree, one of two
// failures follows: a stricter Go rule leaves an account the frontend calls
// complete and every edit rejects, and a stricter SQL rule raises a prompt the
// user cannot clear. Neither is visible from either side alone, so the guard has
// to run both against the same inputs.
//
// The specific trap this catches: PostgreSQL's one-argument btrim() strips ASCII
// spaces only, while Go's strings.TrimSpace strips the whole Unicode whitespace
// set. V010 spells the character set out for exactly this reason, and the
// emergency migration extends the same SQL/Go agreement to control characters.
func TestProfileCompletenessMatchesSQL(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	migrateV1(t, databaseURL)
	database := testutil.OpenGORM(t, databaseURL)

	values := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "ascii spaces", value: "   "},
		{name: "tab", value: "\t"},
		{name: "NEL U+0085", value: "\u0085"},
		{name: "NBSP U+00A0", value: "\u00a0"},
		{name: "ogham space U+1680", value: "\u1680"},
		{name: "en quad U+2000", value: "\u2000"},
		{name: "em space U+2003", value: "\u2003"},
		{name: "line separator U+2028", value: "\u2028"},
		{name: "narrow NBSP U+202F", value: "\u202f"},
		{name: "medium mathematical space U+205F", value: "\u205f"},
		{name: "ideographic space U+3000", value: "\u3000"},
		{name: "mixed whitespace", value: " \t\u00a0\u3000 "},
		{name: "zero-width space U+200B", value: "\u200b"},
		{name: "BOM U+FEFF", value: "\ufeff"},
		{name: "real name", value: "张三"},
		{name: "padded real name", value: "  张三  "},
	}

	for _, test := range values {
		t.Run(test.name, func(t *testing.T) {
			var sqlBlank bool
			if err := database.Raw("SELECT sl_profile_is_blank(?)", test.value).
				Scan(&sqlBlank).Error; err != nil {
				t.Fatalf("call sl_profile_is_blank: %v", err)
			}
			if goBlank := validate.IsBlank(test.value); goBlank != sqlBlank {
				t.Fatalf("blankness disagrees for %q: sl_profile_is_blank=%t, validate.IsBlank=%t",
					test.value, sqlBlank, goBlank)
			}
		})
	}
}

func TestControlCharacterMatchesSQL(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	migrateV1(t, databaseURL)
	database := testutil.OpenGORM(t, databaseURL)

	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "C0", value: "张三\x01", want: true},
		{name: "DEL", value: "张三\x7f", want: true},
		{name: "C1", value: "13800000000\u009f", want: true},
		{name: "plain text", value: "张三", want: false},
		{name: "zero width is not control", value: "张\u200b三", want: false},
		{name: "NBSP is not control", value: "张\u00a0三", want: false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var got bool
			if err := database.Raw("SELECT sl_has_control_character(?)", test.value).Scan(&got).Error; err != nil {
				t.Fatalf("call sl_has_control_character: %v", err)
			}
			if got != test.want || got != validate.HasControlCharacter(test.value) {
				t.Fatalf("control-character result = %t, want SQL/Go=%t", got, test.want)
			}
		})
	}
}

// V016's sl_name_invalid is the SQL half of the product name rule;
// validate.IsInvalidName is the Go half. The rule is a whitelist (Han blocks
// through Unicode 16 plus interpunct variants) because PostgreSQL has no
// \p{Script=Han}, so both sides spell the ranges out. A drift between them has
// the same failure shape as every other half-pair: a name the flag misses
// hides from the completion page while the edit form refuses it forever.
func TestNameRuleMatchesSQL(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	migrateV1(t, databaseURL)
	database := testutil.OpenGORM(t, databaseURL)

	values := []struct {
		name  string
		value string
		trash bool
	}{
		{name: "basic Han", value: "张三", trash: false},
		{name: "single Han", value: "张", trash: false},
		{name: "Han with interpunct", value: "张·三", trash: false},
		{name: "interpunct variant U+30FB", value: "张・三", trash: false},
		{name: "Extension A", value: "\u3400", trash: false},
		{name: "Extension B", value: "\U00020bb7", trash: false},
		{name: "padded name", value: "  张三  ", trash: false},
		{name: "blank", value: "", trash: true},
		{name: "whitespace only", value: "  ", trash: true},
		{name: "latin name", value: "AAA", trash: true},
		{name: "english name", value: "John", trash: true},
		{name: "digits", value: "B24040525", trash: true},
		{name: "control character", value: "张\x01三", trash: true},
		{name: "zero-width space", value: "张\u200b三", trash: true},
		{name: "full-width space", value: "张\u3000三", trash: true},
		{name: "emoji", value: "张😀", trash: true},
	}
	for _, test := range values {
		t.Run(test.name, func(t *testing.T) {
			var sqlTrash bool
			if err := database.Raw("SELECT sl_name_invalid(?)", test.value).
				Scan(&sqlTrash).Error; err != nil {
				t.Fatalf("call sl_name_invalid: %v", err)
			}
			if goTrash := validate.IsInvalidName(test.value); goTrash != sqlTrash {
				t.Fatalf("name-rule disagreement for %q: SQL=%t, Go=%t",
					test.value, sqlTrash, goTrash)
			}
		})
	}
}

// The generated column and IncompleteProfileFields have to answer the same
// question at row level, not just per field: the column is what routes a user to
// the completion page, and the field list is what the page renders.
func TestGeneratedFlagMatchesIncompleteFields(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	migrateV1(t, databaseURL)
	database := testutil.OpenGORM(t, databaseURL)

	// The four shapes measured in the legacy dump, plus the case-sensitivity and
	// invisible-whitespace variants.
	rows := []struct {
		name        string
		userName    string
		phoneNumber string
		qqNumber    string
		major       string
	}{
		{name: "clean", userName: "张三", phoneNumber: "13800000000", qqNumber: "10001", major: "软件工程"},
		{name: "fully dirty", userName: "", phoneNumber: "", qqNumber: "", major: ""},
		{name: "real name blank contact", userName: "李四", phoneNumber: "", qqNumber: "", major: ""},
		{name: "name is student id", userName: "", phoneNumber: "13800000001", qqNumber: "10002", major: "通信工程"},
		{name: "nbsp name", userName: "\u00a0", phoneNumber: "13800000002", qqNumber: "10003", major: "软件工程"},
		{name: "control major", userName: "王五", phoneNumber: "13800000006", qqNumber: "10007", major: "软\u009f件工程"},
		// V016 name-rule cases: out-of-set names must be surfaced as incomplete,
		// while a valid Han name with an interpunct remains complete.
		{name: "latin name", userName: "AAA", phoneNumber: "13800000007", qqNumber: "10008", major: "软件工程"},
		{name: "zero-width name", userName: "\u200b张三", phoneNumber: "13800000008", qqNumber: "10009", major: "软件工程"},
		{name: "interpunct name is complete", userName: "张·三", phoneNumber: "13800000009", qqNumber: "10010", major: "软件工程"},
	}

	for index, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			studentID := fmt.Sprintf("B240400%02d", index)
			userName := row.userName
			// "name is student id" and "fully dirty" carry the placeholder shape the
			// import produced; the lowercase form is what makes the case-insensitive
			// comparison load-bearing.
			switch row.name {
			case "name is student id":
				userName = lower(studentID)
			case "fully dirty":
				userName = studentID
			}

			user := model.User{
				Name:         userName,
				PhoneNumber:  row.phoneNumber,
				QQNumber:     row.qqNumber,
				PasswordHash: "hash",
				StudentID:    studentID,
				LoginEmail:   fmt.Sprintf("b240400%02d@njupt.edu.cn", index),
				Major:        row.major,
			}
			if err := database.Create(&user).Error; err != nil {
				t.Fatalf("create user: %v", err)
			}

			var stored model.User
			if err := database.First(&stored, user.ID).Error; err != nil {
				t.Fatalf("read user: %v", err)
			}

			want := len(validate.IncompleteProfileFields(
				stored.Name, stored.PhoneNumber, stored.QQNumber, stored.Major, stored.StudentID)) > 0
			if stored.ProfileNeedsCompletion != want {
				t.Fatalf("profile_needs_completion = %t, IncompleteProfileFields non-empty = %t (name=%q phone=%q qq=%q major=%q sid=%q)",
					stored.ProfileNeedsCompletion, want,
					stored.Name, stored.PhoneNumber, stored.QQNumber, stored.Major, stored.StudentID)
			}
		})
	}
}

// A generated column may not appear in an INSERT or UPDATE column list, so the
// model's `->` tag is what keeps every existing write path working. Without it
// this Create fails outright, which is why it is asserted rather than assumed.
func TestGeneratedFlagIsReadOnlyThroughGORM(t *testing.T) {
	databaseURL := testutil.StartPostgres(t)
	migrateV1(t, databaseURL)
	database := testutil.OpenGORM(t, databaseURL)

	user := model.User{
		Name:         "B24041000",
		PhoneNumber:  "",
		PasswordHash: "hash",
		StudentID:    "B24041000",
		LoginEmail:   "b24041000@njupt.edu.cn",
		Major:        "",
		// Deliberately set: GORM must drop it rather than send it to PostgreSQL.
		ProfileNeedsCompletion: false,
	}
	if err := database.Create(&user).Error; err != nil {
		t.Fatalf("create user with generated field set: %v", err)
	}

	var stored model.User
	if err := database.First(&stored, user.ID).Error; err != nil {
		t.Fatalf("read user: %v", err)
	}
	if !stored.ProfileNeedsCompletion {
		t.Fatal("profile_needs_completion = false, want true: the struct value was persisted instead of being generated")
	}

	// The "cut access now" paths (password change, demotion, account close) and
	// the legacy-password rehash all UPDATE a user row that may still be dirty.
	// This is the property a CHECK ... NOT VALID constraint would have broken:
	// under one, this update fails and a dirty account can no longer have its
	// tokens revoked.
	if err := database.Model(&model.User{}).Where("id = ?", user.ID).
		UpdateColumn("token_version", gorm.Expr("token_version + 1")).Error; err != nil {
		t.Fatalf("bump token_version on an incomplete row: %v", err)
	}

	// Completing the fields must clear the flag with no application involvement.
	if err := database.Model(&model.User{}).Where("id = ?", user.ID).
		Updates(map[string]any{
			"name":         "赵六",
			"phone_number": "13800001000",
			"qq_number":    "10001",
			"major":        "软件工程",
		}).Error; err != nil {
		t.Fatalf("complete profile: %v", err)
	}
	if err := database.First(&stored, user.ID).Error; err != nil {
		t.Fatalf("re-read user: %v", err)
	}
	if stored.ProfileNeedsCompletion {
		t.Fatal("profile_needs_completion = true after completing every field, want false")
	}
}

func lower(value string) string {
	out := []rune(value)
	for index, symbol := range out {
		if symbol >= 'A' && symbol <= 'Z' {
			out[index] = symbol + ('a' - 'A')
		}
	}
	return string(out)
}
