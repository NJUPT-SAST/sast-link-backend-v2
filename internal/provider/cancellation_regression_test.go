package provider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type reviewDoer func(*http.Request) (*http.Response, error)

func (f reviewDoer) Do(r *http.Request) (*http.Response, error) { return f(r) }
func TestRegressionLarkWaiterHonorsCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	client := larkTestClient(reviewDoer(func(r *http.Request) (*http.Response, error) {
		once.Do(func() { close(started) })
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-release:
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"code":0,"app_access_token":"token","expire":7200}`)), Header: make(http.Header)}, nil
	}), testTenantKey)
	leaderDone := make(chan struct{})
	go func() { defer close(leaderDone); _, _ = client.fetchAppAccessToken(context.Background()) }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	waiterDone := make(chan error, 1)
	go func() { _, err := client.fetchAppAccessToken(ctx); waiterDone <- err }()
	select {
	case err := <-waiterDone:
		t.Logf("canceled waiter returned before leader release; error=%v", err)
	case <-time.After(200 * time.Millisecond):
		t.Error("canceled waiter still blocked on tokenMu after 200ms while leader performs network I/O")
	}
	close(release)
	<-leaderDone
}

func TestRegressionLarkLeaderCancellationDoesNotCancelSharedFetch(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	client := larkTestClient(reviewDoer(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		close(started)
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-release:
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"code":0,"app_access_token":"shared","expire":7200}`)), Header: make(http.Header)}, nil
	}), testTenantKey)
	ctx, cancel := context.WithCancel(context.Background())
	leader := make(chan error, 1)
	go func() { _, err := client.fetchAppAccessToken(ctx); leader <- err }()
	<-started
	cancel()
	if err := <-leader; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error=%v", err)
	}
	follower := make(chan string, 1)
	go func() { token, _ := client.fetchAppAccessToken(context.Background()); follower <- token }()
	close(release)
	if got := <-follower; got != "shared" {
		t.Fatalf("token=%q", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("fetch calls=%d", calls.Load())
	}
}

func TestRegressionLarkFailedFlightCanRetry(t *testing.T) {
	var calls atomic.Int32
	client := larkTestClient(reviewDoer(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"code":1}`)), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"code":0,"app_access_token":"recovered","expire":7200}`)), Header: make(http.Header)}, nil
	}), testTenantKey)
	if _, err := client.fetchAppAccessToken(context.Background()); err == nil {
		t.Fatal("failed flight succeeded")
	}
	if token, err := client.fetchAppAccessToken(context.Background()); err != nil || token != "recovered" {
		t.Fatalf("retry %q %v", token, err)
	}
}
