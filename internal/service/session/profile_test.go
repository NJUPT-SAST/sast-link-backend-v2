package session

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func stringPtr(value string) *string { return &value }

func TestUpdateProfileAppliesOnlyPresentFields(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	before := users.byID[42].PhoneNumber

	result, err := service.UpdateProfile(context.Background(), UpdateProfileInput{
		UserID: 42,
		Name:   stringPtr("  新名字  "),
		Intro:  stringPtr("新的自我介绍"),
	})
	if err != nil {
		t.Fatalf("UpdateProfile returned error: %v", err)
	}
	if result.Profile.Name != "新名字" {
		t.Fatalf("name = %q, want trimmed 新名字", result.Profile.Name)
	}
	if users.byID[42].PhoneNumber != before {
		t.Fatalf("phone_number = %q, want untouched %q", users.byID[42].PhoneNumber, before)
	}
	if got := result.ChangedFields; !slices.Equal(got, []string{"name", "intro"}) {
		t.Fatalf("changed fields = %v, want [name intro]", got)
	}
	update := users.profileUpdates[0]
	if update.PhoneNumber != nil || update.College != nil || update.Department != nil {
		t.Fatalf("absent fields leaked into update: %+v", update)
	}
}

// An explicit empty string clears a nullable display field; an absent key must
// not. Collapsing the two would make "remove my intro" impossible.
func TestUpdateProfileClearsNullableFieldWithEmptyString(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	users.byID[42].Profile.Intro = stringPtr("旧介绍")

	if _, err := service.UpdateProfile(context.Background(), UpdateProfileInput{
		UserID: 42,
		Intro:  stringPtr(""),
	}); err != nil {
		t.Fatalf("UpdateProfile returned error: %v", err)
	}
	if users.byID[42].Profile.Intro != nil {
		t.Fatalf("intro = %v, want nil after explicit empty string", *users.byID[42].Profile.Intro)
	}
}

// Department is an enum column with no "" member, so clearing it must write NULL
// rather than an empty enum value PostgreSQL would reject.
func TestUpdateProfileClearsDepartment(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)

	if _, err := service.UpdateProfile(context.Background(), UpdateProfileInput{
		UserID:     42,
		Department: stringPtr(""),
	}); err != nil {
		t.Fatalf("UpdateProfile returned error: %v", err)
	}
	if users.byID[42].Profile.Department != nil {
		t.Fatalf("department = %v, want nil", *users.byID[42].Profile.Department)
	}
	if got := *users.profileUpdates[0].Department; got != "" {
		t.Fatalf("update department = %q, want empty sentinel", got)
	}
}

// "user" columns are NOT NULL, so a blank value is invalid input rather than a
// clear. Letting it through would store an account with no name.
func TestUpdateProfileRejectsBlankRequiredField(t *testing.T) {
	service := newRegisterService(t)
	_, err := service.UpdateProfile(context.Background(), UpdateProfileInput{
		UserID: 42,
		Name:   stringPtr("   "),
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
	if calls := len(service.Users.(*fakeUsers).profileUpdates); calls != 0 {
		t.Fatalf("repository called %d times, want 0 on invalid input", calls)
	}
}

func TestUpdateProfileRejectsUnknownEnums(t *testing.T) {
	tests := []struct {
		name  string
		input UpdateProfileInput
	}{
		{"college", UpdateProfileInput{UserID: 42, College: stringPtr("不存在学院")}},
		{"department", UpdateProfileInput{UserID: 42, Department: stringPtr("hardware")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newRegisterService(t)
			_, err := service.UpdateProfile(context.Background(), test.input)
			assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
		})
	}
}

// Over-long values must be rejected before the write: PostgreSQL's "value too
// long for type character varying(n)" surfaces as an opaque 500.
func TestUpdateProfileRejectsOverlongValues(t *testing.T) {
	service := newRegisterService(t)
	_, err := service.UpdateProfile(context.Background(), UpdateProfileInput{
		UserID: 42,
		Major:  stringPtr(strings.Repeat("专", maxMajorLength+1)),
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

// blog_url and github_url are rendered as links on the public card, so a
// javascript: scheme would turn every card viewer into a target.
func TestUpdateProfileRejectsNonHTTPLinks(t *testing.T) {
	tests := []string{
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"//evil.example.com",
		"blog.example.com",
	}
	for _, link := range tests {
		t.Run(link, func(t *testing.T) {
			service := newRegisterService(t)
			_, err := service.UpdateProfile(context.Background(), UpdateProfileInput{
				UserID:  42,
				BlogURL: stringPtr(link),
			})
			assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
		})
	}
}

func TestUpdateProfileAcceptsHTTPLinksAndClearing(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	if _, err := service.UpdateProfile(context.Background(), UpdateProfileInput{
		UserID:    42,
		BlogURL:   stringPtr("https://blog.example.com/posts"),
		GitHubURL: stringPtr(""),
	}); err != nil {
		t.Fatalf("UpdateProfile returned error: %v", err)
	}
	if got := users.byID[42].Profile.BlogURL; got == nil || *got != "https://blog.example.com/posts" {
		t.Fatalf("blog_url = %v, want the submitted https URL", got)
	}
	if users.byID[42].Profile.GitHubURL != nil {
		t.Fatalf("github_url = %v, want cleared", *users.byID[42].Profile.GitHubURL)
	}
}

// The display email reaches logs and the public card, so it gets the same
// control-character guard as the addresses used for delivery.
func TestUpdateProfileRejectsMalformedDisplayEmail(t *testing.T) {
	service := newRegisterService(t)
	_, err := service.UpdateProfile(context.Background(), UpdateProfileInput{
		UserID: 42,
		Email:  stringPtr("display@example.com\r\nBcc: victim@example.com"),
	})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

func TestUpdateProfileRejectsEmptyRequest(t *testing.T) {
	service := newRegisterService(t)
	_, err := service.UpdateProfile(context.Background(), UpdateProfileInput{UserID: 42})
	assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
}

// student_id is unique, so a racing edit must name the colliding field instead of
// reporting a generic conflict the user cannot act on.
func TestUpdateProfileMapsStudentIDConflict(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	users.updateProfileErr = uniqueViolation(userStudentIDConstraint)

	_, err := service.UpdateProfile(context.Background(), UpdateProfileInput{
		UserID:    42,
		StudentID: stringPtr("B20000001"),
	})
	assertKind(t, err, KindConflict, errcode.CodeStudentIDOccupied)
}

func TestUpdateProfileRecordsChangedFieldsAudit(t *testing.T) {
	service := newRegisterService(t)
	audit := service.Audit.(*fakeAudit)
	if _, err := service.UpdateProfile(context.Background(), UpdateProfileInput{
		UserID:   42,
		Nickname: stringPtr("新昵称"),
		Major:    stringPtr("软件工程"),
	}); err != nil {
		t.Fatalf("UpdateProfile returned error: %v", err)
	}
	entry := audit.entries[len(audit.entries)-1]
	if entry.Action != "update_profile" || entry.Resource != "user" {
		t.Fatalf("audit entry = %+v, want update_profile on user", entry)
	}
	// Fields are logged in contract order, not map order.
	if got := string(entry.Detail); !strings.Contains(got, `["major","nickname"]`) {
		t.Fatalf("audit detail = %s, want changed_fields [major nickname]", got)
	}
}

func TestUpdateProfileRejectsUnknownUser(t *testing.T) {
	service := newRegisterService(t)
	service.Users.(*fakeUsers).updateProfileErr = repository.ErrNotFound

	_, err := service.UpdateProfile(context.Background(), UpdateProfileInput{
		UserID: 42, Name: stringPtr("新名字"),
	})
	assertKind(t, err, KindInvalidToken, errcode.CodeAccessTokenInvalid)
}
