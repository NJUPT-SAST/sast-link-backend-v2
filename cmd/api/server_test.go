package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type fakeHTTPServer struct {
	listenErr     error
	listenRelease chan struct{}
	shutdownCalls int
}

func (s *fakeHTTPServer) ListenAndServe() error {
	if s.listenRelease != nil {
		<-s.listenRelease
	}
	return s.listenErr
}

func (s *fakeHTTPServer) Shutdown(context.Context) error {
	s.shutdownCalls++
	if s.listenRelease != nil {
		close(s.listenRelease)
	}
	return nil
}

type fakeBackgroundWorker struct {
	runErr error
	stops  int
}

func (w *fakeBackgroundWorker) Run(ctx context.Context) error {
	if w.runErr != nil {
		return w.runErr
	}
	<-ctx.Done()
	w.stops++
	return nil
}

func TestServeStopsWorkersWhenHTTPFails(t *testing.T) {
	original := newHTTPServer
	t.Cleanup(func() { newHTTPServer = original })
	server := &fakeHTTPServer{listenErr: errors.New("bind failed")}
	newHTTPServer = func(string, http.Handler) httpServer { return server }
	background := &fakeBackgroundWorker{}

	err := serve(context.Background(), ":8080", http.NewServeMux(), []backgroundWorker{background})
	if err == nil || !strings.Contains(err.Error(), "bind failed") {
		t.Fatalf("serve() error = %v, want bind failure", err)
	}
	if server.shutdownCalls != 1 || background.stops != 1 {
		t.Fatalf("shutdown calls=%d worker stops=%d", server.shutdownCalls, background.stops)
	}
}

func TestServeStopsHTTPWhenWorkerFails(t *testing.T) {
	original := newHTTPServer
	t.Cleanup(func() { newHTTPServer = original })
	server := &fakeHTTPServer{listenErr: http.ErrServerClosed, listenRelease: make(chan struct{})}
	newHTTPServer = func(string, http.Handler) httpServer { return server }
	background := &fakeBackgroundWorker{runErr: errors.New("worker failed")}

	err := serve(context.Background(), ":8080", http.NewServeMux(), []backgroundWorker{background})
	if err == nil {
		t.Fatal("serve() error = nil, want worker failure")
	}
	if server.shutdownCalls != 1 {
		t.Fatalf("shutdown calls = %d, want 1", server.shutdownCalls)
	}
}

// A panicking worker must not crash the process with a bare stack: serve
// converts the panic into an error carrying the stack, takes the same fast
// shutdown a returned error takes, and exits with a named cause.
func TestServeConvertsWorkerPanicToError(t *testing.T) {
	original := newHTTPServer
	t.Cleanup(func() { newHTTPServer = original })
	server := &fakeHTTPServer{listenErr: http.ErrServerClosed, listenRelease: make(chan struct{})}
	newHTTPServer = func(string, http.Handler) httpServer { return server }
	background := &panicBackgroundWorker{}

	err := serve(context.Background(), ":8080", http.NewServeMux(), []backgroundWorker{background})
	if err == nil {
		t.Fatal("serve() error = nil, want the panic surfaced as an error")
	}
	if !strings.Contains(err.Error(), "background worker panicked") || !strings.Contains(err.Error(), "boom in worker loop") {
		t.Fatalf("serve() error = %v, want the panic value and the sentinel text", err)
	}
	if !strings.Contains(err.Error(), "goroutine") {
		t.Fatalf("serve() error = %v, want the stack trace preserved", err)
	}
	if server.shutdownCalls != 1 {
		t.Fatalf("shutdown calls = %d, want 1: the panic takes the normal exit path", server.shutdownCalls)
	}
}

type panicBackgroundWorker struct{}

func (panicBackgroundWorker) Run(context.Context) error {
	panic("boom in worker loop")
}
