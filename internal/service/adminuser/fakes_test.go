package adminuser

import (
	"context"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

type fakeUsers struct {
	listRows     []repository.AdminUserRow
	listTotal    int64
	listErr      error
	listedFilter repository.AdminUserFilter

	findResult *model.User
	findErr    error

	// Every write fake records the user id it was handed. A mis-targeted write is the
	// one bug in this layer that no other assertion can see: the audit entry is built
	// from the input rather than from what the repository was told, so it stays
	// correct even when the write lands on the wrong row.
	updateCalls    int
	updatedUserID  int64
	updateInput    repository.AdminUserUpdate
	updateEntries  []model.BlacklistEntry
	updateRevoked  bool
	updateErr      error
	deleteCalls    int
	deletedUserID  int64
	deleteEntries  []model.BlacklistEntry
	deleteErr      error
	restoreErr     error
	restoredUserID int64
}

func (f *fakeUsers) ListAdminUsers(
	_ context.Context,
	filter repository.AdminUserFilter,
) ([]repository.AdminUserRow, int64, error) {
	f.listedFilter = filter
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return f.listRows, f.listTotal, nil
}

func (f *fakeUsers) FindByID(_ context.Context, _ int64) (*model.User, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	if f.findResult == nil {
		return nil, repository.ErrNotFound
	}
	return f.findResult, nil
}

func (f *fakeUsers) FindAuthUserByID(_ context.Context, _ int64) (*model.User, error) {
	return f.FindByID(context.Background(), 0)
}

func (f *fakeUsers) UpdateAdminUser(
	_ context.Context,
	userID int64,
	update repository.AdminUserUpdate,
	_ time.Time,
) ([]model.BlacklistEntry, bool, error) {
	f.updateCalls++
	f.updatedUserID = userID
	f.updateInput = update
	if f.updateErr != nil {
		return nil, false, f.updateErr
	}
	return f.updateEntries, f.updateRevoked, nil
}

func (f *fakeUsers) SoftDeleteAndRevokeSessions(
	_ context.Context,
	userID int64,
	_ time.Time,
) ([]model.BlacklistEntry, error) {
	f.deleteCalls++
	f.deletedUserID = userID
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	return f.deleteEntries, nil
}

func (f *fakeUsers) RestoreUser(_ context.Context, userID int64) error {
	f.restoredUserID = userID
	return f.restoreErr
}

func (f *fakeUsers) Stats(_ context.Context) (repository.UserStats, error) {
	return repository.UserStats{
		ByRole:       map[model.UserRole]int64{},
		ByState:      map[model.UserState]int64{},
		ByDepartment: map[model.Department]int64{},
	}, nil
}

func (f *fakeUsers) NamesByIDs(_ context.Context, _ []int64) (map[int64]string, error) {
	return map[int64]string{}, nil
}

type fakeAudit struct {
	entries   []*model.AuditLog
	listed    repository.AuditLogFilter
	listRows  []model.AuditLog
	total     int64
	listErr   error
	createErr error
}

func (f *fakeAudit) Create(_ context.Context, entry *model.AuditLog) error {
	f.entries = append(f.entries, entry)
	return f.createErr
}

func (f *fakeAudit) List(
	_ context.Context,
	filter repository.AuditLogFilter,
) ([]model.AuditLog, int64, error) {
	f.listed = filter
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return f.listRows, f.total, nil
}

type fakeBlacklist struct {
	jtis []string
	err  error
}

func (f *fakeBlacklist) DeleteAuthStates(_ context.Context, jtis []string) error {
	f.jtis = jtis
	return f.err
}

type testClock struct {
	value time.Time
}

func (c testClock) Now() time.Time { return c.value }

var testNow = time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)

const (
	testAdminID  int64 = 99
	testTargetID int64 = 42
)

type harness struct {
	service   Service
	users     *fakeUsers
	audit     *fakeAudit
	blacklist *fakeBlacklist
	devices   *fakeDeviceStore
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	users := &fakeUsers{}
	auditLog := &fakeAudit{}
	blacklist := &fakeBlacklist{}
	devices := &fakeDeviceStore{}
	return &harness{
		service: Service{
			Users:     users,
			Audit:     auditLog,
			Blacklist: blacklist,
			Devices:   devices,
			Clock:     testClock{value: testNow},
		},
		users:     users,
		audit:     auditLog,
		blacklist: blacklist,
		devices:   devices,
	}
}

// targetUser is the account an edit is applied to, by default an ordinary member
// so a test that cares about the admin guards has to opt into them.
func targetUser(role model.UserRole, state model.UserState) *model.User {
	return &model.User{
		ID:           testTargetID,
		Role:         role,
		State:        state,
		Name:         "张三",
		PhoneNumber:  "13800138000",
		QQNumber:     "1234567890",
		StudentID:    "B24040101",
		LoginEmail:   "b24040101@njupt.edu.cn",
		EmailType:    model.EmailTypeNJUpt,
		College:      model.CollegeComputerSoftwareCybersecurity,
		Major:        "软件工程",
		PasswordHash: "hash",
		CreatedAt:    testNow,
		UpdatedAt:    testNow,
	}
}

const (
	testClientIP  = "203.0.113.7"
	testUserAgent = "console"
)

func stringPtr(value string) *string { return &value }

// fakeDeviceStore records RemoveAllDevices calls so tests can assert that a
// session-killing admin action cleared the user's device records.
type fakeDeviceStore struct {
	cleared []int64
	err     error
}

func (f *fakeDeviceStore) RemoveAllDevices(_ context.Context, userID int64) error {
	f.cleared = append(f.cleared, userID)
	return f.err
}

func updateInput(mutate func(*UpdateUserInput)) UpdateUserInput {
	input := UpdateUserInput{
		UserID:      testTargetID,
		AdminUserID: testAdminID,
		ClientIP:    testClientIP,
		UserAgent:   testUserAgent,
	}
	if mutate != nil {
		mutate(&input)
	}
	return input
}

func targetInput() TargetUserInput {
	return TargetUserInput{
		UserID:      testTargetID,
		AdminUserID: testAdminID,
		ClientIP:    testClientIP,
		UserAgent:   testUserAgent,
	}
}
