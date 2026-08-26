package repository_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// testAlumniRequest is a ticket whose fields would provision a complete profile.
func testAlumniRequest(studentID string) *model.AlumniRequest {
	return &model.AlumniRequest{
		Name:          "校友测试",
		StudentID:     studentID,
		LoginEmail:    strings.ToLower(studentID) + "@njupt.edu.cn",
		PersonalEmail: strings.ToLower(studentID) + "@example.com",
		PhoneNumber:   "13800138000",
		QQNumber:      "10000",
		College:       model.CollegeOther,
		Major:         "计算机科学与技术",
		JoinYear:      "2020",
		Status:        model.AlumniRequestStatusPending,
	}
}

// provisionFrom builds the rows an approval inserts, standing in for what the
// service layer does.
func provisionFrom(request *model.AlumniRequest) (*model.User, *model.Profile, *model.Identity) {
	return &model.User{
			Role:         model.UserRoleMember,
			State:        model.UserStateRetiredSAST,
			Name:         request.Name,
			PhoneNumber:  request.PhoneNumber,
			QQNumber:     request.QQNumber,
			StudentID:    request.StudentID,
			LoginEmail:   request.LoginEmail,
			College:      request.College,
			Major:        request.Major,
			PasswordHash: "hash",
		},
		&model.Profile{},
		&model.Identity{Provider: model.LoginMethodOtherMail, ProviderID: request.PersonalEmail}
}

func TestAlumniRequestSchemaAndReview(t *testing.T) {
	database := setupDatabase(t)
	requests := repository.NewAlumniRequest(database)

	// One open ticket per student ID, but a rejected applicant may correct their
	// details and resubmit. That is the whole reason the unique index is partial on
	// status rather than plain.
	t.Run("PendingUniquenessAllowsResubmitAfterRejection", func(t *testing.T) {
		ctx := context.Background()

		first := testAlumniRequest("B20040201")
		if err := requests.Create(ctx, first); err != nil {
			t.Fatalf("Create() first error = %v", err)
		}

		// A second ticket for the same student while the first is pending is refused by
		// uq_alumni_requests_pending_student.
		second := testAlumniRequest("B20040201")
		err := requests.Create(ctx, second)
		if err == nil {
			t.Fatal("Create() with a pending ticket for the same student error = nil")
		}
		if got := repository.DuplicateConstraint(err); got != "uq_alumni_requests_pending_student" {
			t.Fatalf("violated constraint = %q, want the pending-student index", got)
		}

		// The index is on lower(btrim(student_id)), because the previous database's
		// import produced both cases for the same person.
		mixedCase := testAlumniRequest("b20040201")
		mixedCase.LoginEmail = "other@njupt.edu.cn"
		mixedCase.PersonalEmail = "other@example.com"
		if err := requests.Create(ctx, mixedCase); err == nil {
			t.Fatal("Create() with a differently cased student id error = nil, want the index to catch it")
		}

		// Once the first is rejected it no longer occupies the slot.
		if _, err := requests.RejectAlumniRequest(ctx, first.ID, mustUserID(t, database), "信息不符", time.Now().UTC()); err != nil {
			t.Fatalf("RejectAlumniRequest() error = %v", err)
		}
		if err := requests.Create(ctx, testAlumniRequest("B20040201")); err != nil {
			t.Fatalf("Create() after a rejection error = %v, want the resubmission to be allowed", err)
		}
	})

	// Approval provisions the account and writes the verdict in one transaction.
	t.Run("ApprovalProvisionsAndRecordsTheVerdict", func(t *testing.T) {
		ctx := context.Background()
		reviewer := mustUserID(t, database)

		request := testAlumniRequest("B20040202")
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		now := time.Now().UTC().Truncate(time.Millisecond)
		approved, err := requests.ApproveAlumniRequest(ctx, request.ID, reviewer, now,
			func(ticket *model.AlumniRequest) (*model.User, *model.Profile, *model.Identity, error) {
				user, profile, identity := provisionFrom(ticket)
				return user, profile, identity, nil
			})
		if err != nil {
			t.Fatalf("ApproveAlumniRequest() error = %v", err)
		}
		if approved.Status != model.AlumniRequestStatusApproved {
			t.Fatalf("status = %s, want approved", approved.Status)
		}
		if approved.CreatedUserID == nil {
			t.Fatal("created_user_id is NULL after an approval")
		}
		if approved.ReviewedBy == nil || *approved.ReviewedBy != reviewer {
			t.Fatalf("reviewed_by = %v, want %d", approved.ReviewedBy, reviewer)
		}
		if approved.ReviewedAt == nil {
			t.Fatal("reviewed_at is NULL after an approval")
		}

		// The account and its other_mail binding both exist.
		var user model.User
		if err := database.Where("id = ?", *approved.CreatedUserID).Take(&user).Error; err != nil {
			t.Fatalf("read provisioned user: %v", err)
		}
		if user.Role != model.UserRoleMember || user.State != model.UserStateRetiredSAST {
			t.Fatalf("provisioned user = %s/%s, want member/retired_sast", user.Role, user.State)
		}
		var identityCount int64
		if err := database.Model(&model.Identity{}).
			Where("user_id = ? AND provider = ? AND provider_id = ?",
				user.ID, model.LoginMethodOtherMail, request.PersonalEmail).
			Count(&identityCount).Error; err != nil {
			t.Fatalf("count identities: %v", err)
		}
		if identityCount != 1 {
			t.Fatalf("other_mail bindings = %d, want 1; the applicant could not reset a password",
				identityCount)
		}
	})

	// A failed provision must roll back the verdict too, so the reviewer can correct
	// the ticket and retry. A committed verdict with no account would leave the
	// applicant holding an approval for something that does not exist.
	t.Run("ApprovalRollsBackOnProvisionFailure", func(t *testing.T) {
		ctx := context.Background()

		// An existing account already holds the login email the ticket names.
		existing := testUser("b20040206@njupt.edu.cn")
		if err := database.Create(existing).Error; err != nil {
			t.Fatalf("seed existing user: %v", err)
		}

		request := testAlumniRequest("B20040206")
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		_, err := requests.ApproveAlumniRequest(ctx, request.ID, mustUserID(t, database),
			time.Now().UTC(), func(ticket *model.AlumniRequest) (*model.User, *model.Profile, *model.Identity, error) {
				user, profile, identity := provisionFrom(ticket)
				return user, profile, identity, nil
			})
		if err == nil {
			t.Fatal("ApproveAlumniRequest() with a colliding login email error = nil")
		}
		if got := repository.DuplicateConstraint(err); got == "" {
			t.Fatalf("error = %v, want a unique violation the service can classify", err)
		}

		// The ticket is still pending, so the reviewer can fix the address and retry.
		stored, getErr := requests.Get(ctx, request.ID)
		if getErr != nil {
			t.Fatalf("Get() error = %v", getErr)
		}
		if stored.Status != model.AlumniRequestStatusPending {
			t.Fatalf("status = %s, want it still pending after a failed provision", stored.Status)
		}
		if stored.CreatedUserID != nil {
			t.Fatalf("created_user_id = %v, want NULL after a rollback", *stored.CreatedUserID)
		}
	})

	// Closing the provisioned account must not delete the ticket: the FK is
	// ON DELETE SET NULL so the review history survives.
	t.Run("SurvivesTheAccountItCreated", func(t *testing.T) {
		ctx := context.Background()

		request := testAlumniRequest("B20040207")
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		approved, err := requests.ApproveAlumniRequest(ctx, request.ID, mustUserID(t, database),
			time.Now().UTC(), func(ticket *model.AlumniRequest) (*model.User, *model.Profile, *model.Identity, error) {
				user, profile, identity := provisionFrom(ticket)
				return user, profile, identity, nil
			})
		if err != nil {
			t.Fatalf("ApproveAlumniRequest() error = %v", err)
		}

		if deleteErr := database.Where("id = ?", *approved.CreatedUserID).
			Delete(&model.User{}).Error; deleteErr != nil {
			t.Fatalf("delete provisioned user: %v", deleteErr)
		}

		stored, err := requests.Get(ctx, request.ID)
		if err != nil {
			t.Fatalf("Get() after the account was deleted error = %v, want the ticket to survive", err)
		}
		if stored.CreatedUserID != nil {
			t.Fatalf("created_user_id = %v, want NULL after the account was deleted", *stored.CreatedUserID)
		}
	})

	// Reviewing a ticket that already carries a verdict is a state conflict, not a
	// not-found: the ticket exists, the transition is what is refused.
	t.Run("RejectRefusesADecidedTicket", func(t *testing.T) {
		ctx := context.Background()
		reviewer := mustUserID(t, database)

		request := testAlumniRequest("B20040215")
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if _, err := requests.RejectAlumniRequest(ctx, request.ID, reviewer, "信息不符", time.Now().UTC()); err != nil {
			t.Fatalf("RejectAlumniRequest() first error = %v", err)
		}
		_, err := requests.RejectAlumniRequest(ctx, request.ID, reviewer, "再次驳回", time.Now().UTC())
		if !errors.Is(err, repository.ErrStateConflict) {
			t.Fatalf("second rejection error = %v, want ErrStateConflict", err)
		}

		_, err = requests.ApproveAlumniRequest(ctx, request.ID, reviewer, time.Now().UTC(),
			func(*model.AlumniRequest) (*model.User, *model.Profile, *model.Identity, error) {
				t.Error("provision ran for a ticket that already carries a verdict")
				return nil, nil, nil, errors.New("must not be called")
			})
		if !errors.Is(err, repository.ErrStateConflict) {
			t.Fatalf("approval after rejection error = %v, want ErrStateConflict", err)
		}
	})

	t.Run("GetReportsNotFound", func(t *testing.T) {

		if _, err := requests.Get(context.Background(), 999999); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("Get() for a missing ticket error = %v, want ErrNotFound", err)
		}
	})

}

func TestAlumniRequestCompletenessAndConcurrency(t *testing.T) {
	database := setupDatabase(t)
	requests := repository.NewAlumniRequest(database)

	// The provisioned account must clear V010's generated column, or the applicant
	// is sent to a completion page on first login for fields they were never asked
	// for.
	t.Run("ApprovalProducesACompleteProfile", func(t *testing.T) {
		ctx := context.Background()

		request := testAlumniRequest("B20040203")
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		approved, err := requests.ApproveAlumniRequest(ctx, request.ID, mustUserID(t, database),
			time.Now().UTC(), func(ticket *model.AlumniRequest) (*model.User, *model.Profile, *model.Identity, error) {
				user, profile, identity := provisionFrom(ticket)
				return user, profile, identity, nil
			})
		if err != nil {
			t.Fatalf("ApproveAlumniRequest() error = %v", err)
		}

		var needsCompletion bool
		if err := database.Model(&model.User{}).
			Where("id = ?", *approved.CreatedUserID).
			Select("profile_needs_completion").
			Scan(&needsCompletion).Error; err != nil {
			t.Fatalf("read profile_needs_completion: %v", err)
		}
		if needsCompletion {
			t.Fatal("the provisioned account is flagged incomplete; the applicant would land on /profile/complete")
		}
	})

	// The reverse of the assertion above: a blank major does flag the account. This is
	// what makes the previous test meaningful rather than vacuously true, and it is
	// why the service layer requires major even though the column allows empty.
	t.Run("ApprovalWithABlankMajorWouldBeFlagged", func(t *testing.T) {
		ctx := context.Background()

		request := testAlumniRequest("B20040204")
		request.Major = ""
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		approved, err := requests.ApproveAlumniRequest(ctx, request.ID, mustUserID(t, database),
			time.Now().UTC(), func(ticket *model.AlumniRequest) (*model.User, *model.Profile, *model.Identity, error) {
				user, profile, identity := provisionFrom(ticket)
				return user, profile, identity, nil
			})
		if err != nil {
			t.Fatalf("ApproveAlumniRequest() error = %v", err)
		}

		var needsCompletion bool
		if err := database.Model(&model.User{}).
			Where("id = ?", *approved.CreatedUserID).
			Select("profile_needs_completion").
			Scan(&needsCompletion).Error; err != nil {
			t.Fatalf("read profile_needs_completion: %v", err)
		}
		if !needsCompletion {
			t.Fatal("a blank major did not flag the account; V010's rule is not what the service assumes")
		}
	})

	// A double-clicked approve button: both transactions race on the row lock and
	// exactly one provisions an account. Without SELECT ... FOR UPDATE both would
	// insert and the second would fail on the student-ID unique index instead - after
	// having already sent a second approval email.
	t.Run("ConcurrentApprovalsYieldOneAccount", func(t *testing.T) {
		ctx := context.Background()
		reviewer := mustUserID(t, database)

		request := testAlumniRequest("B20040205")
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		var (
			wg        sync.WaitGroup
			mu        sync.Mutex
			successes int
			conflicts int
			others    []error
		)
		start := make(chan struct{})
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := requests.ApproveAlumniRequest(ctx, request.ID, reviewer, time.Now().UTC(),
					func(ticket *model.AlumniRequest) (*model.User, *model.Profile, *model.Identity, error) {
						user, profile, identity := provisionFrom(ticket)
						return user, profile, identity, nil
					})
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					successes++
				case errors.Is(err, repository.ErrStateConflict):
					conflicts++
				default:
					others = append(others, err)
				}
			}()
		}
		close(start)
		wg.Wait()

		if len(others) > 0 {
			t.Fatalf("unexpected errors = %v", others)
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("successes = %d, conflicts = %d, want exactly 1 of each", successes, conflicts)
		}

		var accounts int64
		if err := database.Model(&model.User{}).
			Where("student_id = ?", request.StudentID).Count(&accounts).Error; err != nil {
			t.Fatalf("count accounts: %v", err)
		}
		if accounts != 1 {
			t.Fatalf("provisioned accounts = %d, want 1", accounts)
		}
	})

	// V001's shared trigger function is reused, so updated_at has to advance on write.
	t.Run("UpdatedAtAdvances", func(t *testing.T) {
		ctx := context.Background()

		request := testAlumniRequest("B20040209")
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		original := request.UpdatedAt

		// NOW() is transaction-scoped, so a write in the same instant would compare
		// equal without this.
		time.Sleep(10 * time.Millisecond)
		if _, err := requests.RejectAlumniRequest(ctx, request.ID, mustUserID(t, database),
			"信息不符", time.Now().UTC()); err != nil {
			t.Fatalf("RejectAlumniRequest() error = %v", err)
		}

		stored, err := requests.Get(ctx, request.ID)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if !stored.UpdatedAt.After(original) {
			t.Fatalf("updated_at = %s, want it after %s", stored.UpdatedAt, original)
		}
	})

}

func TestAlumniRequestQueriesAndRetention(t *testing.T) {
	database := setupDatabase(t)
	requests := repository.NewAlumniRequest(database)

	// notify_attempts is counted before a send and notified_at only after success, so
	// the pair distinguishes "tried but unconfirmed" from "never attempted".
	t.Run("NotificationStateWrites", func(t *testing.T) {
		ctx := context.Background()

		request := testAlumniRequest("B20040208")
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		if err := requests.MarkNotifyAttempt(ctx, request.ID); err != nil {
			t.Fatalf("MarkNotifyAttempt() error = %v", err)
		}
		stored, err := requests.Get(ctx, request.ID)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if stored.NotifyAttempts != 1 {
			t.Fatalf("notify_attempts = %d, want 1", stored.NotifyAttempts)
		}
		// A counted attempt with no confirmation is exactly the backlog state the console
		// filters on.
		if stored.NotifiedAt != nil {
			t.Fatal("notified_at was set by counting an attempt")
		}

		now := time.Now().UTC()
		if notifyErr := requests.MarkNotified(ctx, request.ID, now); notifyErr != nil {
			t.Fatalf("MarkNotified() error = %v", notifyErr)
		}
		stored, err = requests.Get(ctx, request.ID)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if stored.NotifiedAt == nil {
			t.Fatal("notified_at is still NULL after MarkNotified")
		}
		// The counter is not disturbed by confirming delivery.
		if stored.NotifyAttempts != 1 {
			t.Fatalf("notify_attempts = %d after MarkNotified, want 1", stored.NotifyAttempts)
		}
	})

	// A reviewed ticket ages out; a pending one never does, however old. The handling
	// target is a statement in the UI, not a rule the backend enforces, and deleting
	// an unreviewed application would lose someone's request.
	t.Run("RetentionSweepsOnlyReviewedAlumniRequests", func(t *testing.T) {
		retention := repository.NewRetention(database)
		ctx := context.Background()
		reviewer := mustUserID(t, database)

		old := time.Now().UTC().Add(-365 * 24 * time.Hour)

		// Rejected long ago: due for sweeping.
		rejected := testAlumniRequest("B20040210")
		if err := requests.Create(ctx, rejected); err != nil {
			t.Fatalf("Create() rejected error = %v", err)
		}
		if _, err := requests.RejectAlumniRequest(ctx, rejected.ID, reviewer, "信息不符", old); err != nil {
			t.Fatalf("RejectAlumniRequest() error = %v", err)
		}

		// Pending since the same date: must survive.
		pending := testAlumniRequest("B20040211")
		if err := requests.Create(ctx, pending); err != nil {
			t.Fatalf("Create() pending error = %v", err)
		}
		if err := database.Model(&model.AlumniRequest{}).Where("id = ?", pending.ID).
			UpdateColumn("created_at", old).Error; err != nil {
			t.Fatalf("age the pending ticket: %v", err)
		}

		removed, err := retention.DeleteExpiredAlumniRequests(ctx, time.Now().UTC().Add(-24*time.Hour), 100)
		if err != nil {
			t.Fatalf("DeleteExpiredAlumniRequests() error = %v", err)
		}
		// At least this subtest's own aged rejection. Not an exact count: the subtests
		// here share one database, so earlier ones may have left reviewed tickets of
		// their own, and pinning the number would couple this assertion to their
		// contents. What matters is asserted precisely below - which specific rows
		// survived.
		if removed < 1 {
			t.Fatalf("removed = %d, want at least the aged rejection", removed)
		}
		if _, err := requests.Get(ctx, rejected.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("the reviewed ticket survived the sweep (err = %v)", err)
		}
		if _, err := requests.Get(ctx, pending.ID); err != nil {
			t.Fatalf("the pending ticket was swept: %v", err)
		}
	})

	// The queue read filters by status and by notification state, and matches a
	// keyword across the identifying columns.
	//
	// Every assertion is scoped by a keyword unique to this subtest rather than
	// counting the whole table: the subtests here share one database, so a global
	// count would couple this test to how many tickets the ones above happened to
	// leave behind.
	t.Run("ListFilters", func(t *testing.T) {
		ctx := context.Background()
		reviewer := mustUserID(t, database)
		const marker = "ListFilters小明"

		first := testAlumniRequest("B20040212")
		first.Name = marker
		if err := requests.Create(ctx, first); err != nil {
			t.Fatalf("Create() first error = %v", err)
		}
		second := testAlumniRequest("B20040213")
		second.Name = marker
		if err := requests.Create(ctx, second); err != nil {
			t.Fatalf("Create() second error = %v", err)
		}
		if _, err := requests.RejectAlumniRequest(ctx, second.ID, reviewer, "信息不符", time.Now().UTC()); err != nil {
			t.Fatalf("RejectAlumniRequest() error = %v", err)
		}

		pendingStatus := model.AlumniRequestStatusPending
		rows, total, err := requests.List(ctx, repository.AlumniRequestFilter{
			Status: &pendingStatus, Keyword: marker, Limit: 10,
		})
		if err != nil {
			t.Fatalf("List() by status error = %v", err)
		}
		if total != 1 || len(rows) != 1 || rows[0].ID != first.ID {
			t.Fatalf("status filter returned %d rows (total %d), want just the pending one", len(rows), total)
		}

		rows, _, err = requests.List(ctx, repository.AlumniRequestFilter{Keyword: marker, Limit: 10})
		if err != nil {
			t.Fatalf("List() by keyword error = %v", err)
		}
		if len(rows) != 2 {
			t.Fatalf("keyword filter returned %d rows, want both of this subtest's tickets", len(rows))
		}

		// Neither has been notified yet, so the un-notified filter sees both.
		notified := false
		_, total, err = requests.List(ctx, repository.AlumniRequestFilter{
			Notified: &notified, Keyword: marker, Limit: 10,
		})
		if err != nil {
			t.Fatalf("List() by notified error = %v", err)
		}
		if total != 2 {
			t.Fatalf("un-notified total = %d, want 2", total)
		}

		if notifyErr := requests.MarkNotified(ctx, second.ID, time.Now().UTC()); notifyErr != nil {
			t.Fatalf("MarkNotified() error = %v", notifyErr)
		}
		_, total, err = requests.List(ctx, repository.AlumniRequestFilter{
			Notified: &notified, Keyword: marker, Limit: 10,
		})
		if err != nil {
			t.Fatalf("List() by notified error = %v", err)
		}
		if total != 1 {
			t.Fatalf("un-notified total after one delivery = %d, want 1", total)
		}
	})

	// A keyword holding LIKE metacharacters is matched literally, so a submitted "%"
	// cannot widen the search to every row.
	t.Run("ListEscapesLikeMetacharacters", func(t *testing.T) {
		ctx := context.Background()

		if err := requests.Create(ctx, testAlumniRequest("B20040214")); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		_, total, err := requests.List(ctx, repository.AlumniRequestFilter{Keyword: "%", Limit: 10})
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if total != 0 {
			t.Fatalf("a literal %% matched %d rows, want 0", total)
		}
	})

}

// mustUserID seeds a reviewer account and returns its id, since reviewed_by is a
// foreign key.
//
// Both the login email and the student ID are made unique per call: the subtests
// in this file share one database, and "user" carries a unique index on each of
// those columns, so a fixed value would make the second caller fail on a
// collision that has nothing to do with what it is testing.
func mustUserID(t *testing.T, database *gorm.DB) int64 {
	t.Helper()
	unique := strconv.FormatInt(reviewerSeq.Add(1), 10)
	reviewer := testUser("reviewer-alumni-" + unique + "@sast.fun")
	reviewer.StudentID = "REVIEWER" + unique
	if err := database.Create(reviewer).Error; err != nil {
		t.Fatalf("seed reviewer: %v", err)
	}
	return reviewer.ID
}

// reviewerSeq numbers the seeded reviewers. An atomic counter rather than a
// timestamp: the concurrency subtest seeds from parallel goroutines, and a
// second-resolution clock would hand two of them the same identifiers.
var reviewerSeq atomic.Int64

// TestAlumniRequestApprovalRefusesAFoldedStudentID pins the approval-time
// folded occupancy check: an existing account holding b24040525 must make a
// ticket for B24040525 unapprovable rather than provision a second account, and
// the ticket must stay pending so the reviewer can act on it.
func TestAlumniRequestApprovalRefusesAFoldedStudentID(t *testing.T) {
	database := setupDatabase(t)
	requests := repository.NewAlumniRequest(database)
	ctx := context.Background()

	existing := &model.User{
		Name:         "Existing Lowercase",
		PhoneNumber:  "13800138000",
		QQNumber:     "10000",
		PasswordHash: "password-hash",
		LoginEmail:   "folded-b24040525@njupt.edu.cn",
		StudentID:    "b24040525",
		Role:         model.UserRoleMember,
		State:        model.UserStateRetiredSAST,
		College:      model.CollegeOther,
	}
	if err := database.Create(existing).Error; err != nil {
		t.Fatalf("seed existing user: %v", err)
	}

	request := testAlumniRequest("B24040525")
	// Keep the ticket's own addresses clear of the seeded account: only the
	// student ID is under test.
	request.LoginEmail = "alumni-B24040525@njupt.edu.cn"
	request.PersonalEmail = "alumni-B24040525@example.com"
	if err := requests.Create(ctx, request); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	_, err := requests.ApproveAlumniRequest(ctx, request.ID, mustUserID(t, database),
		time.Now().UTC(), func(ticket *model.AlumniRequest) (*model.User, *model.Profile, *model.Identity, error) {
			user, profile, identity := provisionFrom(ticket)
			return user, profile, identity, nil
		})
	if !errors.Is(err, repository.ErrStudentIDExists) {
		t.Fatalf("ApproveAlumniRequest() error = %v, want ErrStudentIDExists", err)
	}

	stored, err := requests.Get(ctx, request.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if stored.Status != model.AlumniRequestStatusPending {
		t.Fatalf("status = %s, want still pending after a folded refusal", stored.Status)
	}
	if stored.CreatedUserID != nil {
		t.Fatalf("created_user_id = %v, want NULL after a folded refusal", *stored.CreatedUserID)
	}
}

// TestAlumniRequestEmailHasPendingTicket pins the cross-ticket email guard: an
// address with a ticket awaiting review is refused at submit time, while a
// reviewed ticket releases the address so a corrected applicant may resubmit —
// the same release the partial student-ID index gives. The login_email column
// counts too, since it is the address that becomes the account's login.
func TestAlumniRequestEmailHasPendingTicket(t *testing.T) {
	database := setupDatabase(t)
	requests := repository.NewAlumniRequest(database)
	ctx := context.Background()

	request := testAlumniRequest("B20040211")
	if err := requests.Create(ctx, request); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	for _, probe := range []string{request.PersonalEmail, request.LoginEmail} {
		pending, err := requests.EmailHasPendingTicket(ctx, probe)
		if err != nil {
			t.Fatalf("EmailHasPendingTicket(%q) error = %v", probe, err)
		}
		if !pending {
			t.Fatalf("EmailHasPendingTicket(%q) = false, want true", probe)
		}
	}

	unrelated, err := requests.EmailHasPendingTicket(ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("EmailHasPendingTicket(nobody) error = %v", err)
	}
	if unrelated {
		t.Fatal("EmailHasPendingTicket(nobody) = true, want false")
	}

	// A reviewed ticket releases the address. Rejection is the resubmit path: a
	// fixed application carries the same personal email.
	if _, rejectErr := requests.RejectAlumniRequest(ctx, request.ID, mustUserID(t, database),
		"请补充毕业证明", time.Now().UTC()); rejectErr != nil {
		t.Fatalf("RejectAlumniRequest() error = %v", rejectErr)
	}
	after, err := requests.EmailHasPendingTicket(ctx, request.PersonalEmail)
	if err != nil {
		t.Fatalf("EmailHasPendingTicket(after reject) error = %v", err)
	}
	if after {
		t.Fatal("EmailHasPendingTicket(after reject) = true, want false: reviewed tickets release the address")
	}
}

// TestAlumniRequestListUnnotifiedReviewed pins the restart self-heal input: a
// crash loses whatever the in-memory queue held, and only reviewed tickets with
// notify_attempts = 0 represent jobs the previous process never touched. An
// attempted-but-unconfirmed delivery (attempts >= 1) must stay out — it sits in
// the console backlog for the resend endpoint instead of risking a duplicate.
func TestAlumniRequestListUnnotifiedReviewed(t *testing.T) {
	database := setupDatabase(t)
	requests := repository.NewAlumniRequest(database)
	ctx := context.Background()

	makeTicket := func(t *testing.T, studentID string, status model.AlumniRequestStatus) *model.AlumniRequest {
		t.Helper()
		request := testAlumniRequest(studentID)
		if status == model.AlumniRequestStatusPending {
			t.Fatalf("pending tickets are not reviewed; use approve/reject paths")
		}
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		var verdict error
		if status == model.AlumniRequestStatusApproved {
			_, verdict = requests.ApproveAlumniRequest(ctx, request.ID, mustUserID(t, database),
				time.Now().UTC(), func(ticket *model.AlumniRequest) (*model.User, *model.Profile, *model.Identity, error) {
					user, profile, identity := provisionFrom(ticket)
					return user, profile, identity, nil
				})
		} else {
			_, verdict = requests.RejectAlumniRequest(ctx, request.ID, mustUserID(t, database),
				"请补齐资料", time.Now().UTC())
		}
		if verdict != nil {
			t.Fatalf("verdict on %s error = %v", studentID, verdict)
		}
		return request
	}

	t.Run("untouched reviewed tickets are listed", func(t *testing.T) {
		// Two fresh tickets: approved and rejected, neither notified.
		approved := makeTicket(t, "B20040212", model.AlumniRequestStatusApproved)
		rejected := makeTicket(t, "B20040213", model.AlumniRequestStatusRejected)

		rows, err := requests.ListUnnotifiedReviewed(ctx, 10)
		if err != nil {
			t.Fatalf("ListUnnotifiedReviewed() error = %v", err)
		}
		if len(rows) != 2 {
			t.Fatalf("listed %d rows, want 2", len(rows))
		}
		byID := map[int64]model.AlumniRequest{}
		for _, row := range rows {
			byID[row.ID] = row
		}
		if _, ok := byID[approved.ID]; !ok {
			t.Fatal("approved ticket not listed")
		}
		if _, ok := byID[rejected.ID]; !ok {
			t.Fatal("rejected ticket not listed")
		}
		if byID[rejected.ID].RejectReason != "请补齐资料" {
			t.Fatalf("reject_reason = %q, want it carried for the email", byID[rejected.ID].RejectReason)
		}
	})

	t.Run("attempted tickets are skipped", func(t *testing.T) {
		ticket := makeTicket(t, "B20040214", model.AlumniRequestStatusApproved)
		if err := requests.MarkNotifyAttempt(ctx, ticket.ID); err != nil {
			t.Fatalf("MarkNotifyAttempt() error = %v", err)
		}

		rows, err := requests.ListUnnotifiedReviewed(ctx, 10)
		if err != nil {
			t.Fatalf("ListUnnotifiedReviewed() error = %v", err)
		}
		for _, row := range rows {
			if row.ID == ticket.ID {
				t.Fatalf("attempted ticket %d listed, want it skipped", ticket.ID)
			}
		}
	})

	t.Run("the limit is respected", func(t *testing.T) {
		rows, err := requests.ListUnnotifiedReviewed(ctx, 1)
		if err != nil {
			t.Fatalf("ListUnnotifiedReviewed(1) error = %v", err)
		}
		if len(rows) > 1 {
			t.Fatalf("limit 1 returned %d rows", len(rows))
		}
	})
}

// TestAlumniRequestRecoveryApproval pins the recovery path end to end at the
// repository level: approval binds the ticket's personal email to the account
// its student ID already names, writes created_user_id, and never provisions.
func TestAlumniRequestRecoveryApproval(t *testing.T) {
	database := setupDatabase(t)
	requests := repository.NewAlumniRequest(database)
	ctx := context.Background()

	t.Run("binds and records without provisioning", func(t *testing.T) {
		existing := testUser("recovered-b20040215@njupt.edu.cn")
		if err := database.Create(existing).Error; err != nil {
			t.Fatalf("seed existing user: %v", err)
		}

		request := testAlumniRequest(existing.StudentID)
		// The ticket's login email must name the seeded account, exactly as a real
		// recovery submission must.
		request.LoginEmail = existing.LoginEmail
		request.Intent = model.AlumniRequestIntentRecover
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		approved, err := requests.ApproveAlumniRequestRecover(ctx, request.ID,
			mustUserID(t, database), time.Now().UTC())
		if err != nil {
			t.Fatalf("ApproveAlumniRequestRecover() error = %v", err)
		}
		if approved.Status != model.AlumniRequestStatusApproved {
			t.Fatalf("status = %s, want approved", approved.Status)
		}
		if approved.CreatedUserID == nil || *approved.CreatedUserID != existing.ID {
			t.Fatalf("created_user_id = %v, want the recovered account %d",
				approved.CreatedUserID, existing.ID)
		}

		var count int64
		if err := database.Model(&model.Identity{}).
			Where("user_id = ? AND provider = ? AND provider_id = ?",
				existing.ID, model.LoginMethodOtherMail, request.PersonalEmail).
			Count(&count).Error; err != nil {
			t.Fatalf("count bound identity: %v", err)
		}
		if count != 1 {
			t.Fatalf("bound identity count = %d, want 1", count)
		}
	})

	t.Run("a case-differing student id still reaches the account", func(t *testing.T) {
		// The folded lookup is what makes a resubmission with b24040525-style
		// casing resolve instead of reporting a missing target.
		existing := testUser("folded-recover@njupt.edu.cn")
		existing.StudentID = "b24040525"
		if err := database.Create(existing).Error; err != nil {
			t.Fatalf("seed lowercase user: %v", err)
		}

		request := testAlumniRequest("B24040525")
		request.LoginEmail = existing.LoginEmail
		request.Intent = model.AlumniRequestIntentRecover
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		approved, err := requests.ApproveAlumniRequestRecover(ctx, request.ID,
			mustUserID(t, database), time.Now().UTC())
		if err != nil {
			t.Fatalf("ApproveAlumniRequestRecover(folded) error = %v", err)
		}
		if approved.CreatedUserID == nil || *approved.CreatedUserID != existing.ID {
			t.Fatalf("created_user_id = %v, want %d", approved.CreatedUserID, existing.ID)
		}
	})

	t.Run("a mismatched login email refuses the approval", func(t *testing.T) {
		existing := testUser("mismatch-b20040216@njupt.edu.cn")
		if err := database.Create(existing).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}

		request := testAlumniRequest(existing.StudentID)
		request.LoginEmail = "not-the-record-b20040216@njupt.edu.cn"
		request.Intent = model.AlumniRequestIntentRecover
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		_, err := requests.ApproveAlumniRequestRecover(ctx, request.ID,
			mustUserID(t, database), time.Now().UTC())
		if !errors.Is(err, repository.ErrLoginEmailMismatch) {
			t.Fatalf("error = %v, want ErrLoginEmailMismatch", err)
		}
		stored, getErr := requests.Get(ctx, request.ID)
		if getErr != nil || stored.Status != model.AlumniRequestStatusPending {
			t.Fatalf("ticket state after refusal: status=%v err=%v, want still pending",
				stored.Status, getErr)
		}
	})

	t.Run("a closed account is refused", func(t *testing.T) {
		users := repository.NewUser(database)
		existing := testUser("closed-b20040217@njupt.edu.cn")
		if err := database.Create(existing).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		if _, err := users.SoftDeleteAndRevokeSessions(ctx, existing.ID, time.Now().UTC()); err != nil {
			t.Fatalf("close account: %v", err)
		}

		request := testAlumniRequest(existing.StudentID)
		request.LoginEmail = existing.LoginEmail
		request.Intent = model.AlumniRequestIntentRecover
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		_, err := requests.ApproveAlumniRequestRecover(ctx, request.ID,
			mustUserID(t, database), time.Now().UTC())
		if !errors.Is(err, repository.ErrAccountClosed) {
			t.Fatalf("error = %v, want ErrAccountClosed", err)
		}
	})

	t.Run("a misdirected provision approval refuses a recover ticket", func(t *testing.T) {
		// The service dispatches on intent; the repository guards keep a wrong
		// call from provisioning beside a recovery target.
		existing := testUser("guarded-b20040218@njupt.edu.cn")
		if err := database.Create(existing).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}

		request := testAlumniRequest(existing.StudentID)
		request.Intent = model.AlumniRequestIntentRecover
		if err := requests.Create(ctx, request); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		_, err := requests.ApproveAlumniRequest(ctx, request.ID, mustUserID(t, database),
			time.Now().UTC(), func(ticket *model.AlumniRequest) (*model.User, *model.Profile, *model.Identity, error) {
				user, profile, identity := provisionFrom(ticket)
				return user, profile, identity, nil
			})
		if !errors.Is(err, repository.ErrInvalidArgument) {
			t.Fatalf("error = %v, want ErrInvalidArgument for an intent mismatch", err)
		}
	})
}
