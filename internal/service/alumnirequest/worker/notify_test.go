package alumnirequestworker_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/mailer"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/alumnirequest"
	alumnirequestworker "github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/alumnirequest/worker"
)

// fakeRequests records the delivery-state writes in order, which is what makes the
// count-before-send guarantee assertable.
type fakeRequests struct {
	mu       sync.Mutex
	calls    []string
	attempts int
	notified int
	markErr  error
	// listRows feeds the startup reconcile.
	listRows []model.AlumniRequest
	listErr  error
}

func (f *fakeRequests) MarkNotifyAttempt(_ context.Context, _ int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "attempt")
	f.attempts++
	return f.markErr
}

func (f *fakeRequests) MarkNotified(_ context.Context, _ int64, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "notified")
	f.notified++
	return nil
}

func (f *fakeRequests) ListUnnotifiedReviewed(_ context.Context, limit int, excludeIDs []int64) ([]model.AlumniRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	excluded := make(map[int64]struct{}, len(excludeIDs))
	for _, id := range excludeIDs {
		excluded[id] = struct{}{}
	}
	rows := make([]model.AlumniRequest, 0, limit)
	for _, row := range f.listRows {
		if _, skip := excluded[row.ID]; skip {
			continue
		}
		rows = append(rows, row)
		if len(rows) == limit {
			break
		}
	}
	return rows, nil
}

func (f *fakeRequests) sequence() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeRequests) attemptCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts
}

func (f *fakeRequests) notifiedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.notified
}

// fakeMailer records what was sent and can fail on demand.
type fakeMailer struct {
	mu       sync.Mutex
	sent     []mailer.AlumniResult
	to       []string
	err      error
	onCalled func()
}

func (f *fakeMailer) SendAlumniRequestResult(_ context.Context, to string, result mailer.AlumniResult) error {
	f.mu.Lock()
	f.sent = append(f.sent, result)
	f.to = append(f.to, to)
	f.mu.Unlock()
	if f.onCalled != nil {
		f.onCalled()
	}
	return f.err
}

func (f *fakeMailer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fakeMailer) resultAt(i int) mailer.AlumniResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent[i]
}

func (f *fakeMailer) recipientAt(i int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.to[i]
}

// runWorker starts the consumer and returns a stop function.
func runWorker(t *testing.T, worker *alumnirequestworker.Notifier) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := worker.Run(ctx); err != nil {
			t.Errorf("Run() error = %v", err)
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func TestEnqueueIsNonBlockingAndBounded(t *testing.T) {
	t.Parallel()

	worker := alumnirequestworker.New(&fakeRequests{}, &fakeMailer{},
		"https://link.sast.fun/reset", "link@sast.fun")

	// Nothing is consuming, so the queue fills and then refuses. It must refuse
	// rather than block: the caller is finishing an HTTP request whose review has
	// already committed.
	accepted := 0
	for i := range 200 {
		if worker.EnqueueAlumniNotification(alumnirequest.NotificationJob{RequestID: int64(i)}) {
			accepted++
		}
	}
	if accepted == 0 {
		t.Fatal("no jobs were accepted")
	}
	if accepted == 200 {
		t.Fatal("every job was accepted; the queue is not bounded")
	}
}

// A nil worker is what a deployment without the worker wired would hand the
// service. It has to answer false rather than panic, so notify_enqueued reports the
// truth.
func TestEnqueueOnANilWorkerReportsFalse(t *testing.T) {
	t.Parallel()

	var worker *alumnirequestworker.Notifier
	if worker.EnqueueAlumniNotification(alumnirequest.NotificationJob{RequestID: 1}) {
		t.Fatal("a nil worker accepted a job")
	}
}

func TestRunRequiresItsDependencies(t *testing.T) {
	t.Parallel()

	// A queue with no mailer cannot deliver anything, and silently consuming jobs
	// would drop the applicant's only instruction to set a password.
	worker := alumnirequestworker.New(&fakeRequests{}, nil, "https://x/reset", "s@x")
	if err := worker.Run(context.Background()); err == nil {
		t.Fatal("Run() with no mailer error = nil, want a refusal")
	}
}

// The attempt is counted before the send. A process killed mid-send then leaves
// notify_attempts incremented with notified_at NULL, which reads as "tried, not
// confirmed" - the truth. Counting afterwards would discard the evidence.
func TestProcessCountsTheAttemptBeforeSending(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{}
	sent := make(chan struct{})
	emailer := &fakeMailer{onCalled: func() { close(sent) }}
	worker := alumnirequestworker.New(requests, emailer, "https://link.sast.fun/reset", "link@sast.fun")
	stop := runWorker(t, worker)
	defer stop()

	if !worker.EnqueueAlumniNotification(alumnirequest.NotificationJob{
		RequestID: 7, Recipient: "zhangsan@example.com", Name: "张三", Approved: true,
	}) {
		t.Fatal("the job was not accepted")
	}
	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("the mailer was never called")
	}

	// At the moment the mailer ran, the attempt was already recorded.
	sequence := requests.sequence()
	if len(sequence) == 0 || sequence[0] != "attempt" {
		t.Fatalf("write sequence = %v, want the attempt counted first", sequence)
	}
}

func TestProcessMarksNotifiedOnlyAfterASuccessfulSend(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{}
	emailer := &fakeMailer{}
	worker := alumnirequestworker.New(requests, emailer, "https://link.sast.fun/reset", "link@sast.fun")
	stop := runWorker(t, worker)
	defer stop()

	worker.EnqueueAlumniNotification(alumnirequest.NotificationJob{
		RequestID: 7, Recipient: "zhangsan@example.com", Name: "张三", Approved: true,
	})
	waitFor(t, func() bool { return requests.notifiedCount() == 1 })

	if got := requests.sequence(); len(got) != 2 || got[0] != "attempt" || got[1] != "notified" {
		t.Fatalf("write sequence = %v, want attempt then notified", got)
	}
	if emailer.recipientAt(0) != "zhangsan@example.com" {
		t.Fatalf("recipient = %q, want the personal email", emailer.recipientAt(0))
	}
	// The reset URL comes from configuration, not from the job: the applicant needs
	// a working link and a job-supplied one would be attacker-influenced input on an
	// email the service sends.
	if emailer.resultAt(0).ResetURL != "https://link.sast.fun/reset" {
		t.Fatalf("reset url = %q, want the configured one", emailer.resultAt(0).ResetURL)
	}
}

// A failed send must leave notified_at unset, which is exactly what the console's
// backlog filter looks for.
func TestProcessLeavesNotifiedUnsetWhenTheSendFails(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{}
	emailer := &fakeMailer{err: errors.New("smtp refused")}
	worker := alumnirequestworker.New(requests, emailer, "https://link.sast.fun/reset", "link@sast.fun")
	stop := runWorker(t, worker)
	defer stop()

	worker.EnqueueAlumniNotification(alumnirequest.NotificationJob{
		RequestID: 7, Recipient: "zhangsan@example.com", Name: "张三", Approved: true,
	})
	waitFor(t, func() bool { return requests.attemptCount() == 1 })
	// Give the worker room to have made a further write if it were going to.
	time.Sleep(100 * time.Millisecond)

	if requests.notifiedCount() != 0 {
		t.Fatal("notified_at was written despite a failed send")
	}
}

// Failing to count the attempt must not stop the email the applicant is waiting
// for: the counter is diagnostics, the email is the product.
func TestProcessStillSendsWhenTheCounterWriteFails(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{markErr: errors.New("db down")}
	emailer := &fakeMailer{}
	worker := alumnirequestworker.New(requests, emailer, "https://link.sast.fun/reset", "link@sast.fun")
	stop := runWorker(t, worker)
	defer stop()

	worker.EnqueueAlumniNotification(alumnirequest.NotificationJob{
		RequestID: 7, Recipient: "zhangsan@example.com", Name: "张三", Approved: true,
	})
	waitFor(t, func() bool { return emailer.count() == 1 })
}

// A rejection carries the reason through to the mailer, which refuses to send
// without one.
func TestProcessPassesTheRejectionReasonThrough(t *testing.T) {
	t.Parallel()

	requests := &fakeRequests{}
	emailer := &fakeMailer{}
	worker := alumnirequestworker.New(requests, emailer, "https://link.sast.fun/reset", "link@sast.fun")
	stop := runWorker(t, worker)
	defer stop()

	worker.EnqueueAlumniNotification(alumnirequest.NotificationJob{
		RequestID: 7, Recipient: "zhangsan@example.com", Name: "张三",
		Approved: false, RejectReason: "学号与姓名不匹配",
	})
	waitFor(t, func() bool { return emailer.count() == 1 })

	result := emailer.resultAt(0)
	if result.Approved {
		t.Fatal("Approved = true for a rejection")
	}
	if result.RejectReason != "学号与姓名不匹配" {
		t.Fatalf("reason = %q, want the reviewer's reason", result.RejectReason)
	}
	if result.SupportEmail != "link@sast.fun" {
		t.Fatalf("support email = %q, want the configured one", result.SupportEmail)
	}
}

// waitFor polls a condition, failing the test if it never holds.
func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition was never met")
}

// TestRunReconcilesTheQueueOnStartup pins the restart self-heal: a process that
// died with reviewed-but-untouched tickets re-queues them on boot, so an
// applicant whose result email was lost to a crash is served without an admin
// noticing a backlog. The attempt counter moves at send time, never here — a
// reconciled row is not claimed, it is queued; asserting the counter still reads
// the number of sends pins that the reconcile itself never double-counts.
func TestRunReconcilesTheQueueOnStartup(t *testing.T) {
	requests := &fakeRequests{listRows: []model.AlumniRequest{
		{ID: 11, PersonalEmail: "alice@example.com", Name: "甲",
			Status: model.AlumniRequestStatusApproved, Intent: model.AlumniRequestIntentProvision},
		{ID: 12, PersonalEmail: "bob@example.com", Name: "乙",
			Status: model.AlumniRequestStatusRejected, RejectReason: "请补齐资料"},
		{ID: 13, PersonalEmail: "carol@example.com", Name: "丙",
			Status: model.AlumniRequestStatusApproved, Intent: model.AlumniRequestIntentRecover},
	}}
	mailer := &fakeMailer{}
	worker := alumnirequestworker.New(requests, mailer,
		"https://link.sast.fun/reset", "link@sast.fun")

	delivered := make(chan struct{}, 3)
	mailer.onCalled = func() { delivered <- struct{}{} }
	stop := runWorker(t, worker)

	for range 3 {
		select {
		case <-delivered:
		case <-time.After(3 * time.Second):
			t.Fatalf("reconciled notification not delivered; sent %d", mailer.count())
		}
	}
	stop()

	if mailer.count() != 3 {
		t.Fatalf("sent %d, want 3 reconciled notifications", mailer.count())
	}
	if requests.attemptCount() != 3 {
		t.Fatalf("attempts %d, want 3 claims before the sends", requests.attemptCount())
	}
	if got := mailer.resultAt(0); !got.Approved || got.Recovered {
		t.Fatalf("first result = %+v, want a plain approval", got)
	}
	if got := mailer.resultAt(1); got.Approved || got.RejectReason != "请补齐资料" {
		t.Fatalf("second result = %+v, want a rejection carrying the reason", got)
	}
	// A recovered ticket reads as approved to the mailer but selects the
	// restore-access copy, not the new-account one.
	if got := mailer.resultAt(2); !got.Approved || !got.Recovered {
		t.Fatalf("third result = %+v, want an approved recovery", got)
	}
}

// TestRunReconcileSpansBatches pins that a backlog longer than one reconcile
// batch is fully re-queued: the walk excludes already-queued ids, so the oldest
// batch cannot shadow the rest until the worker catches up.
func TestRunReconcileSpansBatches(t *testing.T) {
	rows := make([]model.AlumniRequest, 0, 96)
	for i := range 96 {
		rows = append(rows, model.AlumniRequest{
			ID: int64(100 + i), PersonalEmail: "row@example.com", Name: "批量",
			Status: model.AlumniRequestStatusApproved,
		})
	}
	requests := &fakeRequests{listRows: rows}
	mailer := &fakeMailer{}
	worker := alumnirequestworker.New(requests, mailer,
		"https://link.sast.fun/reset", "link@sast.fun")

	delivered := make(chan struct{}, len(rows))
	mailer.onCalled = func() { delivered <- struct{}{} }
	stop := runWorker(t, worker)

	for range len(rows) {
		select {
		case <-delivered:
		case <-time.After(3 * time.Second):
			stop()
			t.Fatalf("reconciled %d/%d notifications before timeout", mailer.count(), len(rows))
		}
	}
	stop()

	if mailer.count() != len(rows) {
		t.Fatalf("sent %d, want all %d reconciled", mailer.count(), len(rows))
	}
}

// TestRunReconcileFailureIsLoggedNotFatal pins that a broken backlog read leaves
// the worker running: delivery of later jobs must not depend on the reconcile.
func TestRunReconcileFailureIsLoggedNotFatal(t *testing.T) {
	requests := &fakeRequests{listErr: errors.New("boom")}
	mailer := &fakeMailer{}
	worker := alumnirequestworker.New(requests, mailer,
		"https://link.sast.fun/reset", "link@sast.fun")
	// The callback is set before the worker starts: assigning it afterward races
	// the send goroutine's read of the field.
	delivered := make(chan struct{}, 1)
	mailer.onCalled = func() { delivered <- struct{}{} }
	stop := runWorker(t, worker)

	if !worker.EnqueueAlumniNotification(alumnirequest.NotificationJob{
		RequestID: 21, Recipient: "carol@example.com", Name: "丙", Approved: true,
	}) {
		t.Fatal("enqueue failed")
	}
	select {
	case <-delivered:
	case <-time.After(3 * time.Second):
		t.Fatalf("job not delivered after a failed reconcile; sent %d", mailer.count())
	}
	stop()
}
