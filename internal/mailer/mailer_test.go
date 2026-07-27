package mailer

import (
	"context"
	"net"
	"testing"
	"time"
)

// The semaphore must queue sends beyond the cap and release the slot after
// each send, or a verification-code burst would dial unbounded SMTP
// connections — and the context must still be honored while queued.
func TestMailerSemaphoreBoundsConcurrentSends(t *testing.T) {
	// Unroutable address: dialing fails fast instead of hanging on timeout.
	unroutable, err := net.ResolveTCPAddr("tcp", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("resolve addr: %v", err)
	}
	_ = unroutable

	m := New(Config{Host: "127.0.0.1", Port: 1, From: "noreply@example.test", MaxConcurrent: 1})

	// Occupy the only slot by hand; a queued send must block until it frees.
	m.sem <- struct{}{}
	blocked := make(chan error, 1)
	go func() {
		blocked <- m.Send(context.Background(), []string{"user@example.test"}, "subject", "body")
	}()

	select {
	case err := <-blocked:
		t.Fatalf("Send completed while semaphore full: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	<-m.sem // release; the queued send now proceeds and fails at dial
	select {
	case err := <-blocked:
		if err == nil {
			t.Fatal("Send after release returned nil error, want dial failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send still blocked after semaphore release")
	}
	if len(m.sem) != 0 {
		t.Fatalf("semaphore len = %d, want 0 after released send", len(m.sem))
	}
}

func TestMailerSemaphoreRespectsContextCancellation(t *testing.T) {
	m := New(Config{Host: "127.0.0.1", Port: 1, From: "noreply@example.test", MaxConcurrent: 1})
	m.sem <- struct{}{}
	defer func() { <-m.sem }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Send(ctx, []string{"user@example.test"}, "subject", "body"); err == nil {
		t.Fatal("Send with canceled context returned nil error")
	}
}
