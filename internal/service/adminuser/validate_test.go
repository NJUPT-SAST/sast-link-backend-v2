package adminuser

import (
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// The V001 trigger auto_set_email_type only recomputes email_type when
// login_email is in the UPDATE column list, so a request carrying email_type alone
// would store a value contradicting the address. It is accepted only alongside the
// address it agrees with.
func TestValidateEmailTypeRequiresMatchingLoginEmail(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		loginEmail *string
		emailType  string
		wantErr    bool
	}{
		{"matching sast", stringPtr("someone@sast.fun"), string(model.EmailTypeSAST), false},
		{"matching njupt", stringPtr("b24040101@njupt.edu.cn"), string(model.EmailTypeNJUpt), false},
		{"contradicting the domain", stringPtr("someone@sast.fun"), string(model.EmailTypeNJUpt), true},
		{"without a login email", nil, string(model.EmailTypeSAST), true},
		{"not a known type", stringPtr("someone@sast.fun"), "gmail", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := validateUpdate(updateInput(func(input *UpdateUserInput) {
				input.LoginEmail = testCase.loginEmail
				input.EmailType = stringPtr(testCase.emailType)
			}))
			if testCase.wantErr && err == nil {
				t.Fatal("validateUpdate = nil, want a rejection")
			}
			if !testCase.wantErr && err != nil {
				t.Fatalf("validateUpdate = %v, want acceptance", err)
			}
		})
	}
}

// The trigger raises a bare PostgreSQL exception for an unknown domain, which
// would surface as an opaque 500. Rejecting here names the rule instead.
func TestValidateLoginEmailEnforcesAllowedDomains(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"njupt", "b24040101@njupt.edu.cn", false},
		{"sast", "someone@sast.fun", false},
		{"outside domain", "someone@gmail.com", true},
		{"lookalike suffix", "someone@evil-njupt.edu.cn.attacker.test", true},
		{"empty", "   ", true},
		{"two at signs", "a@b@njupt.edu.cn", true},
		{"crlf injection", "someone@njupt.edu.cn\r\nBcc: x@y.test", true},
		{"display name brackets", "<someone@njupt.edu.cn>", true},
		{"comma separated", "a@njupt.edu.cn,b@njupt.edu.cn", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := validateLoginEmail(&testCase.email)
			if testCase.wantErr && err == nil {
				t.Fatalf("validateLoginEmail(%q) = nil, want a rejection", testCase.email)
			}
			if !testCase.wantErr && err != nil {
				t.Fatalf("validateLoginEmail(%q) = %v, want acceptance", testCase.email, err)
			}
		})
	}
}

// The address is lowercased so it matches the unique index and the trigger's
// LOWER() comparison the same way the session flow's normalization does.
func TestValidateLoginEmailNormalizesCase(t *testing.T) {
	email, err := validateLoginEmail(stringPtr("  B24040101@NJUPT.edu.CN  "))
	if err != nil {
		t.Fatalf("validateLoginEmail: %v", err)
	}
	if *email != "b24040101@njupt.edu.cn" {
		t.Fatalf("normalized = %q, want the lowercased trimmed address", *email)
	}
}

// The "user" columns are NOT NULL, so a blank identity field is a rejection rather
// than a clear. major defaults to ” in V001 and is the one an administrator may
// legitimately blank.
func TestValidateUpdateRejectsBlankRequiredFields(t *testing.T) {
	for _, field := range []struct {
		name  string
		apply func(*UpdateUserInput)
	}{
		{"name", func(i *UpdateUserInput) { i.Name = stringPtr("  ") }},
		{"phone_number", func(i *UpdateUserInput) { i.PhoneNumber = stringPtr("") }},
		{"qq_number", func(i *UpdateUserInput) { i.QQNumber = stringPtr("") }},
		{"student_id", func(i *UpdateUserInput) { i.StudentID = stringPtr(" ") }},
	} {
		t.Run(field.name, func(t *testing.T) {
			if _, err := validateUpdate(updateInput(field.apply)); err == nil {
				t.Fatalf("validateUpdate = nil, want %s rejected when blank", field.name)
			}
		})
	}

	validated, err := validateUpdate(updateInput(func(i *UpdateUserInput) { i.Major = stringPtr("") }))
	if err != nil {
		t.Fatalf("blanking major = %v, want acceptance", err)
	}
	if validated.major == nil || *validated.major != "" {
		t.Fatalf("major = %v, want an empty string written", validated.major)
	}
}

// Rejecting an over-long value here turns an opaque PostgreSQL "value too long"
// 500 into a 400 naming the field. Lengths are counted in runes, so a 255-character
// Chinese name is not 765 characters long.
func TestValidateUpdateBoundsFieldLengths(t *testing.T) {
	if _, err := validateUpdate(updateInput(func(i *UpdateUserInput) {
		i.Name = stringPtr(strings.Repeat("名", maxNameLength))
	})); err != nil {
		t.Fatalf("a %d-rune name = %v, want acceptance", maxNameLength, err)
	}
	if _, err := validateUpdate(updateInput(func(i *UpdateUserInput) {
		i.Name = stringPtr(strings.Repeat("名", maxNameLength+1))
	})); err == nil {
		t.Fatal("an over-long name was accepted")
	}
	if _, err := validateUpdate(updateInput(func(i *UpdateUserInput) {
		i.StudentID = stringPtr(strings.Repeat("B", maxStudentIDLength+1))
	})); err == nil {
		t.Fatal("an over-long student_id was accepted")
	}
}

// Control characters would corrupt the audit detail and any console that renders
// these fields.
func TestValidateUpdateRejectsControlCharacters(t *testing.T) {
	if _, err := validateUpdate(updateInput(func(i *UpdateUserInput) {
		i.Name = stringPtr("张\x00三")
	})); err == nil {
		t.Fatal("a NUL in name was accepted")
	}
}

func TestValidateUpdateRejectsUnknownEnums(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		apply func(*UpdateUserInput)
	}{
		{"college", func(i *UpdateUserInput) { i.College = stringPtr("霍格沃兹") }},
		{"role", func(i *UpdateUserInput) { i.Role = stringPtr("superadmin") }},
		{"state", func(i *UpdateUserInput) { i.State = stringPtr("retired") }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := validateUpdate(updateInput(testCase.apply)); err == nil {
				t.Fatalf("validateUpdate = nil, want an unknown %s rejected", testCase.name)
			}
		})
	}
}

// changed_fields drives the audit detail, so it must read in contract order
// regardless of which fields were present.
func TestValidateUpdateReportsChangedFieldsInContractOrder(t *testing.T) {
	validated, err := validateUpdate(updateInput(func(i *UpdateUserInput) {
		i.EmailType = stringPtr(string(model.EmailTypeSAST))
		i.LoginEmail = stringPtr("someone@sast.fun")
		i.Role = stringPtr(string(model.UserRoleMember))
		i.Name = stringPtr("张三")
	}))
	if err != nil {
		t.Fatalf("validateUpdate: %v", err)
	}
	want := []string{"name", "login_email", "role", "email_type"}
	if len(validated.changed) != len(want) {
		t.Fatalf("changed = %v, want %v", validated.changed, want)
	}
	for index, field := range want {
		if validated.changed[index] != field {
			t.Fatalf("changed = %v, want %v", validated.changed, want)
		}
	}
}

// An absent parameter arrives as zero and means "use the default"; an oversized
// page is capped rather than rejected, matching the documented maximum.
func TestNormalizePaging(t *testing.T) {
	for _, testCase := range []struct {
		name                       string
		page, pageSize, defaultSze int
		wantPage, wantSize         int
	}{
		{"defaults", 0, 0, defaultUserPageSize, 1, defaultUserPageSize},
		{"audit default", 0, 0, defaultAuditPageSize, 1, defaultAuditPageSize},
		{"explicit", 3, 25, defaultUserPageSize, 3, 25},
		{"over the cap", 1, 5000, defaultUserPageSize, 1, maxPageSize},
		{"negative page", -4, 10, defaultUserPageSize, 1, 10},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			page, size := normalizePaging(testCase.page, testCase.pageSize, testCase.defaultSze)
			if page != testCase.wantPage || size != testCase.wantSize {
				t.Fatalf("normalizePaging = %d/%d, want %d/%d",
					page, size, testCase.wantPage, testCase.wantSize)
			}
		})
	}
}
