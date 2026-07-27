package mailer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	var config net.ListenConfig
	listener, err := config.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return listener
}

func listenerHostPort(t *testing.T, listener net.Listener) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, parsedPort
}

// The semaphore must queue sends beyond the cap and release the slot after
// each send, or a verification-code burst would dial unbounded SMTP
// connections — and the context must still be honored while queued.
func TestMailerSemaphoreBoundsConcurrentSends(t *testing.T) {
	m := New(Config{Host: "127.0.0.1", Port: 1, From: "noreply@example.test", MaxConcurrent: 1})

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

	<-m.sem
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
	if err := m.Send(ctx, []string{"user@example.test"}, "subject", "body"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send error = %v, want context.Canceled", err)
	}
}

func TestSendSTARTTLSCancellationClosesActiveConnection(t *testing.T) {
	listener := listenLocal(t)
	defer listener.Close()

	connected := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(conn, "220 test ESMTP\r\n")
		reader := bufio.NewReader(conn)
		if _, readErr := reader.ReadString('\n'); readErr != nil {
			return
		}
		close(connected)
		for {
			if _, readErr := reader.ReadByte(); readErr != nil {
				close(closed)
				return
			}
		}
	}()

	host, smtpPort := listenerHostPort(t, listener)
	m := New(Config{Host: host, Port: smtpPort, From: "noreply@example.test", MaxConcurrent: 1})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- m.Send(ctx, []string{"user@example.test"}, "subject", "body") }()

	select {
	case <-connected:
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP client did not reach active I/O")
	}
	cancel()
	select {
	case sendErr := <-result:
		if !errors.Is(sendErr, context.Canceled) {
			t.Fatalf("Send error = %v, want context.Canceled", sendErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Send did not return after cancellation")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not observe connection close")
	}
	if len(m.sem) != 0 {
		t.Fatalf("semaphore len = %d, want 0 after I/O stopped", len(m.sem))
	}
}

func TestSendSTARTTLSRejectsPlaintextServer(t *testing.T) {
	listener := listenLocal(t)
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(conn, "220 test ESMTP\r\n")
		reader := bufio.NewReader(conn)
		line, readErr := reader.ReadString('\n')
		if readErr == nil && strings.HasPrefix(line, "EHLO ") {
			_, _ = fmt.Fprint(conn, "250 test\r\n")
		}
	}()

	host, smtpPort := listenerHostPort(t, listener)
	m := New(Config{Host: host, Port: smtpPort, From: "noreply@example.test", MaxConcurrent: 1})
	sendErr := m.Send(context.Background(), []string{"user@example.test"}, "subject", "body")
	if sendErr == nil || !strings.Contains(sendErr.Error(), "does not advertise STARTTLS") {
		t.Fatalf("Send error = %v, want STARTTLS requirement", sendErr)
	}
}
