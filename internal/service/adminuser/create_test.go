package adminuser

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// createProbeInput is a well-formed provisioning request, so a test that cares
// about one field can mutate just that one.
func createProbeInput() CreateUserInput {
	return CreateUserInput{
		Name:        "张三",
		PhoneNumber: "13800138000",
		QQNumber:    "12345",
		StudentID:   "B24040525",
		LoginEmail:  "b24040525@njupt.edu.cn",
		// The authenticated administrator, the same actor every console write
		// attributes to.
		AdminUserID: testAdminID,
		ClientIP:    testClientIP,
		UserAgent:   testUserAgent,
	}
}

// A provision with a personal email binds it as an other_mail identity in the
// same call, returns the initial password exactly once, and derives a hash the
// password verifies against.
func TestCreateUserProvisionsWithBoundEmail(t *testing.T) {
	h := newHarness(t)
	input := createProbeInput()
	input.PersonalEmail = stringPtr("zhangsan@qq.com")

	result, err := h.service.CreateUser(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if result.UserID != 2001 || result.LoginEmail != "b24040525@njupt.edu.cn" {
		t.Fatalf("result = %+v, want the fake's assigned id and the login email", result)
	}
	if result.InitialPassword == "" {
		t.Fatal("initial password empty, want a generated one")
	}
	if h.users.createdIdentity == nil {
		t.Fatal("created identity = nil, want the personal email bound")
	}
	if h.users.createdIdentity.Provider != model.LoginMethodOtherMail ||
		h.users.createdIdentity.ProviderID != "zhangsan@qq.com" {
		t.Fatalf("identity = %+v, want other_mail zhangsan@qq.com", h.users.createdIdentity)
	}
	if err := h.service.Passwords.VerifyPassword(context.Background(), result.InitialPassword, h.users.createdUser.PasswordHash); err != nil {
		t.Fatalf("stored hash does not verify the returned initial password: %v", err)
	}
	entry := assertAudited(t, h, actionCreateUser, true, 0)
	if !bytes.Contains([]byte(entry.Detail), []byte(`"bound_email":"zhangsan@qq.com"`)) {
		t.Fatalf("audit detail = %s, want the bound email recorded", entry.Detail)
	}
}

// role and state are optional at creation and default to the population this
// endpoint exists for; college defaults to the V001 row default. A provision
// without a personal email creates no identity.
func TestCreateUserDefaultsRoleStateAndCollege(t *testing.T) {
	h := newHarness(t)
	input := createProbeInput()

	result, err := h.service.CreateUser(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if result.UserID == 0 {
		t.Fatal("no user id returned")
	}
	user := h.users.createdUser
	if user.Role != model.UserRoleMember || user.State != model.UserStateRetiredSAST {
		t.Fatalf("role/state = %s/%s, want member/retired_sast", user.Role, user.State)
	}
	if user.College != model.CollegeOther || user.Major != "" {
		t.Fatalf("college/major = %q/%q, want 其他/''", user.College, user.Major)
	}
	if h.users.createdIdentity != nil {
		t.Fatalf("created identity = %+v, want none without a personal email", h.users.createdIdentity)
	}
}

// The bound personal email and the login email are one address: the V005
// trigger would raise on the identity insert, so the service names the mistake
// up front as a 400 instead of a constraint error.
func TestCreateUserRejectsPersonalEmailEqualToLogin(t *testing.T) {
	h := newHarness(t)
	input := createProbeInput()
	input.PersonalEmail = stringPtr(input.LoginEmail)

	_, err := h.service.CreateUser(context.Background(), input)
	assertKind(t, err, KindInvalidInput)
	if h.users.createCalls != 0 {
		t.Fatalf("create calls = %d, want the contradiction refused before the repository", h.users.createCalls)
	}
	assertAudited(t, h, actionCreateUser, false, errcode.CodeBadRequest)
}

// Every rule the account row depends on is checked the same way an edit's is:
// required fields, the login domain, role/state enum membership.
func TestCreateUserRejectsInvalidInput(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*CreateUserInput)
	}{
		{"empty name", func(input *CreateUserInput) { input.Name = "   " }},
		{"empty student id", func(input *CreateUserInput) { input.StudentID = "" }},
		{"login email off-domain", func(input *CreateUserInput) { input.LoginEmail = "zhangsan@qq.com" }},
		{"bad role", func(input *CreateUserInput) { input.Role = stringPtr("boss") }},
		{"control char in name", func(input *CreateUserInput) { input.Name = "张\x00三" }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t)
			input := createProbeInput()
			testCase.mutate(&input)

			_, err := h.service.CreateUser(context.Background(), input)
			assertKind(t, err, KindInvalidInput)
			if h.users.createCalls != 0 {
				t.Fatalf("create calls = %d, want %s refused before the repository", h.users.createCalls, testCase.name)
			}
		})
	}
}

// A brand-new account cannot be created already closed: the state transitions
// that revoke everything run on update/delete paths, so this refusal mirrors
// the update endpoint's and names the contradiction as a state conflict.
func TestCreateUserRejectsDeletedState(t *testing.T) {
	h := newHarness(t)
	input := createProbeInput()
	input.State = stringPtr("is_deleted")

	_, err := h.service.CreateUser(context.Background(), input)
	assertKind(t, err, KindStateConflict)
	if h.users.createCalls != 0 {
		t.Fatal("create calls != 0, want the closed state refused before the repository")
	}
}

// A personal email already serving another account (as its login email or as a
// bound identity) is refused with the column-naming conflict code, and the
// failure audit names the login email that was attempted.
func TestCreateUserFailsWhenPersonalEmailOccupied(t *testing.T) {
	h := newHarness(t)
	h.users.existsEmails = map[string]bool{"zhangsan@qq.com": true}
	input := createProbeInput()
	input.PersonalEmail = stringPtr("zhangsan@qq.com")

	_, err := h.service.CreateUser(context.Background(), input)
	assertMappedTo(t, err, KindConflict, errcode.CodeEmailAlreadyRegistered)
	if h.users.createCalls != 0 {
		t.Fatalf("create calls = %d, want the occupied email refused before the repository", h.users.createCalls)
	}
	entry := assertAudited(t, h, actionCreateUser, false, errcode.CodeEmailAlreadyRegistered)
	if !bytes.Contains([]byte(entry.Detail), []byte(`"login_email":"b24040525@njupt.edu.cn"`)) {
		t.Fatalf("failure audit detail = %s, want the attempted login email named", entry.Detail)
	}
	if !bytes.Contains([]byte(entry.Detail), []byte(`"attempted_personal_email":"zhangsan@qq.com"`)) {
		t.Fatalf("failure audit detail = %s, want the attempted personal email named", entry.Detail)
	}
}

// A duplicate from the racing transaction names the colliding column the same
// way an edit's does: the "user_login_email_key" constraint becomes "邮箱已被占用".
func TestCreateUserMapsLoginEmailCollision(t *testing.T) {
	h := newHarness(t)
	h.users.createErr = &pgconn.PgError{Code: pgerrcode.UniqueViolation, ConstraintName: "user_login_email_key"}
	h.users.existsEmails = map[string]bool{}

	_, err := h.service.CreateUser(context.Background(), createProbeInput())
	assertMappedTo(t, err, KindConflict, errcode.CodeEmailAlreadyRegistered)
	assertAudited(t, h, actionCreateUser, false, errcode.CodeEmailAlreadyRegistered)
}

// An unmapped constraint is not guessed at: it surfaces as a conflict named by
// its own message, matching the edit path.
func TestCreateUserMapsStudentIDCollision(t *testing.T) {
	h := newHarness(t)
	h.users.createErr = &pgconn.PgError{Code: pgerrcode.UniqueViolation, ConstraintName: "user_student_id_key"}

	_, err := h.service.CreateUser(context.Background(), createProbeInput())
	assertMappedTo(t, err, KindConflict, errcode.CodeStudentIDOccupied)
}

// V005's mirror trigger fires when the personal email bound by an admin races a
// registration for an address that is already somebody's login email. It names
// the same outcome as the login-email constraint: an occupied mailbox.
func TestCreateUserMapsIdentityNotLoginEmailCollision(t *testing.T) {
	h := newHarness(t)
	h.users.createErr = &pgconn.PgError{Code: pgerrcode.UniqueViolation, ConstraintName: "ck_identities_provider_id_not_login_email"}

	_, err := h.service.CreateUser(context.Background(), createProbeInput())
	assertMappedTo(t, err, KindConflict, errcode.CodeEmailAlreadyRegistered)
}

// A non-duplicate repository failure is an internal error, and the audit row
// still records the attempt.
func TestCreateUserMapsRepositoryFailureToInternal(t *testing.T) {
	h := newHarness(t)
	h.users.createErr = errSentinel{}

	_, err := h.service.CreateUser(context.Background(), createProbeInput())
	assertMappedTo(t, err, KindInternal, errcode.CodeInternal)
	assertAudited(t, h, actionCreateUser, false, errcode.CodeInternal)
}

// errSentinel is a repository failure that is not a SQL unique violation, so
// the mapping falls through to the internal branch rather than naming a column.
type errSentinel struct{}

func (errSentinel) Error() string { return "repository exploded" }
