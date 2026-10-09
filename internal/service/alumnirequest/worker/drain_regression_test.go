package alumnirequestworker_test

import (
	"context"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/mailer"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/alumnirequest"
	alumnirequestworker "github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/alumnirequest/worker"
)

type reviewDrainMailer struct{ started chan struct{} }

func (m reviewDrainMailer) SendAlumniRequestResult(ctx context.Context, _ string, _ mailer.AlumniResult) error {
	close(m.started)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}
func TestRegressionNotifierDrainsInflightBeforeCancel(t *testing.T) {
	requests := &fakeRequests{}
	mail := reviewDrainMailer{make(chan struct{})}
	worker := alumnirequestworker.New(requests, mail, "https://example.test/reset", "support@example.test")
	stop := runWorker(t, worker)
	worker.EnqueueAlumniNotification(alumnirequest.NotificationJob{RequestID: 1, Recipient: "fixture@example.test", Approved: true})
	<-mail.started
	stop()
	t.Logf("attempts=%d notified=%d", requests.attemptCount(), requests.notifiedCount())
	if requests.notifiedCount() != 1 {
		t.Error("shutdown canceled an in-flight 100ms delivery instead of draining it within the 5s budget")
	}
}

type blockingDrainMailer struct {
	started  chan struct{}
	canceled chan struct{}
}

func (m blockingDrainMailer) SendAlumniRequestResult(ctx context.Context, _ string, _ mailer.AlumniResult) error {
	close(m.started)
	<-ctx.Done()
	close(m.canceled)
	return ctx.Err()
}
func TestRegressionNotifierCapsDrainAndDoesNotTakeNextJob(t *testing.T) {
	requests := &fakeRequests{}
	mail := blockingDrainMailer{make(chan struct{}), make(chan struct{})}
	worker := alumnirequestworker.New(requests, mail, "https://example.test/reset", "support@example.test")
	stop := runWorker(t, worker)
	worker.EnqueueAlumniNotification(alumnirequest.NotificationJob{RequestID: 1})
	<-mail.started
	worker.EnqueueAlumniNotification(alumnirequest.NotificationJob{RequestID: 2})
	start := time.Now()
	stop()
	select {
	case <-mail.canceled:
	case <-time.After(time.Second):
		t.Fatal("in-flight mail not canceled at grace expiry")
	}
	if elapsed := time.Since(start); elapsed < 4900*time.Millisecond || elapsed > 6*time.Second {
		t.Fatalf("drain duration=%v", elapsed)
	}
	if requests.attemptCount() != 1 {
		t.Fatalf("started next queued job: attempts=%d", requests.attemptCount())
	}
}
