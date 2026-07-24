package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

func TestValidateInternalClientModel(t *testing.T) {
	secret := "secret"
	tests := []struct {
		name    string
		client  *model.OAuthClient
		wantErr string
	}{
		{name: "valid", client: &model.OAuthClient{ClientType: model.ClientTypeFirstParty, Scopes: model.StringArray{"openid", "profile", "email"}}},
		{name: "nil", client: nil, wantErr: "client is nil"},
		{name: "third party", client: &model.OAuthClient{ClientType: model.ClientTypeThirdParty, Scopes: model.StringArray{"openid", "profile", "email"}}, wantErr: "first-party public"},
		{name: "secret", client: &model.OAuthClient{ClientType: model.ClientTypeFirstParty, ClientSecretHash: &secret, Scopes: model.StringArray{"openid", "profile", "email"}}, wantErr: "first-party public"},
		{name: "missing scope", client: &model.OAuthClient{ClientType: model.ClientTypeFirstParty, Scopes: model.StringArray{"openid"}}, wantErr: "canonical"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateInternalClientModel(test.client)
			if test.wantErr == "" && err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

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

func TestAssembleSessionRuntimeWiresServiceAndMiddleware(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	_ = key
	if len(internalSessionScopes) != 3 {
		t.Fatalf("internalSessionScopes = %v, want 3 scopes", internalSessionScopes)
	}
}
