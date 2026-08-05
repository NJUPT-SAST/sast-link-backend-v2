package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// cmdMix runs the realistic mixed workload: N long-lived sessions, each a single
// device. Per session, reads dominate (70%), refresh happens per access-TTL and
// on the refresh weight (15%), fresh logins model new sessions (10%), and the
// OAuth token endpoint exercises the same refresh family over /oauth/token (5%).
func cmdMix(args []string) error {
	fs := flag.NewFlagSet("mix", flag.ExitOnError)
	bf := newBenchFlags(fs)
	// The default matches the server's production JWT_ACCESS_TOKEN_EXPIRY (1h);
	// the 1c1g bench overrides it to 60s via -access-ttl so refresh happens more
	// than once per run. A wrong value skews the refresh weight ~12x.
	accessTTL := fs.Duration("access-ttl", time.Hour, "bench access-token TTL (matches JWT_ACCESS_TOKEN_EXPIRY)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := loadPool(bf.pool)
	if err != nil {
		return err
	}
	client := newAPIClient(bf.base)

	hist := make(map[string]*Histogram)
	errs := &ErrorCounter{}
	for _, name := range []string{"profile", "refresh", "login", "oauth"} {
		hist[name] = &Histogram{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(bf.dur)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < bf.conc; i++ {
		user := p.Entries[i%len(p.Entries)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			runSession(ctx, client, user, *accessTTL, hist, errs)
		}()
	}
	wg.Wait()

	total := 0
	for _, name := range []string{"profile", "refresh", "login", "oauth"} {
		p50, p99, p999, n := hist[name].Report()
		total += n
		fmt.Printf("  %-8s n=%-6d p50=%s p99=%s p999=%s\n", name, n, p50, p99, p999)
	}
	fmt.Printf("  total requests=%d errors: %s\n", total, errs.String())
	return nil
}

// runSession simulates one device: it logs in once, then loops picking actions by
// weight until the deadline. The whole session is mutex-serialized, which is both
// realistic (one device does one request at a time) and mandatory for refresh
// rotation — a refresh consumes the current refresh token, so two concurrent
// refreshes would trip the replay defense and revoke the family.
func runSession(
	ctx context.Context,
	client *apiClient,
	user poolEntry,
	accessTTL time.Duration,
	hist map[string]*Histogram,
	errs *ErrorCounter,
) {
	s := &sessionState{client: client, user: user}
	// A failed initial login means the pool is unusable; log and return.
	if err := s.reLogin(ctx); err != nil {
		fmt.Printf("mix: session login failed: %v\n", err)
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		s.step(ctx, accessTTL, hist, errs)
	}
}

type sessionState struct {
	client  *apiClient
	user    poolEntry
	mu      sync.Mutex
	access  string
	refresh string
	issued  time.Time
}

// step performs one action. Called serially per session.
func (s *sessionState) step(ctx context.Context, accessTTL time.Duration, hist map[string]*Histogram, errs *ErrorCounter) {
	// Refresh when the access token is near expiry; a real client does the same.
	if s.issued.IsZero() || time.Since(s.issued) > accessTTL*4/5 {
		s.doRefresh(ctx, hist, errs)
		return
	}
	switch r := rand.Float64(); { // #nosec G404 -- bench traffic weights, not a security primitive
	case r < 0.70:
		s.doProfile(ctx, hist, errs)
	case r < 0.85:
		s.doRefresh(ctx, hist, errs)
	case r < 0.95:
		s.doLogin(ctx, hist, errs)
	default:
		s.doOAuth(ctx, hist, errs)
	}
}

func (s *sessionState) doProfile(ctx context.Context, hist map[string]*Histogram, errs *ErrorCounter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	start := time.Now()
	status, err := s.client.profile(ctx, s.access)
	record(hist["profile"], start, errs, status, err)
}

func (s *sessionState) doRefresh(ctx context.Context, hist map[string]*Histogram, errs *ErrorCounter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	start := time.Now()
	pair, err := s.client.refresh(ctx, s.refresh)
	record(hist["refresh"], start, errs, statusOf(err, 0), err)
	if err != nil {
		// Replay defense or an expired family: rebuild the session.
		_ = s.reLogin(ctx)
		return
	}
	s.access, s.refresh, s.issued = pair.AccessToken, pair.RefreshToken, time.Now()
}

func (s *sessionState) doLogin(ctx context.Context, hist map[string]*Histogram, errs *ErrorCounter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reLoginWithHistogram(ctx, hist, errs)
}

func (s *sessionState) doOAuth(ctx context.Context, hist map[string]*Histogram, errs *ErrorCounter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	start := time.Now()
	pair, err := s.client.oauthToken(ctx, s.refresh)
	record(hist["oauth"], start, errs, statusOf(err, 0), err)
	if err != nil {
		_ = s.reLogin(ctx)
		return
	}
	s.access, s.refresh, s.issued = pair.AccessToken, pair.RefreshToken, time.Now()
}

// reLogin acquires a fresh token pair for the session. Caller must hold s.mu
// except for the initial call in runSession.
func (s *sessionState) reLogin(ctx context.Context) error {
	pair, err := s.client.login(ctx, s.user.Email, s.user.Password)
	if err != nil {
		return err
	}
	s.access, s.refresh, s.issued = pair.AccessToken, pair.RefreshToken, time.Now()
	return nil
}

func (s *sessionState) reLoginWithHistogram(ctx context.Context, hist map[string]*Histogram, errs *ErrorCounter) {
	start := time.Now()
	pair, err := s.client.login(ctx, s.user.Email, s.user.Password)
	record(hist["login"], start, errs, statusOf(err, 0), err)
	if err != nil {
		return
	}
	s.access, s.refresh, s.issued = pair.AccessToken, pair.RefreshToken, time.Now()
}

func record(h *Histogram, start time.Time, errs *ErrorCounter, status int, err error) {
	h.Add(time.Since(start))
	if err != nil || status >= 400 {
		errs.Record(statusOf(err, status))
	}
}

// statusOf returns the HTTP status embedded in an apiError, falling back to the
// status the caller already saw (profile returns a non-2xx status with a nil
// error), and 0 for a transport error.
func statusOf(err error, fallback int) int {
	if err == nil {
		return fallback
	}
	var apiErr *apiError
	if errors.As(err, &apiErr) {
		return apiErr.Status
	}
	return 0
}
