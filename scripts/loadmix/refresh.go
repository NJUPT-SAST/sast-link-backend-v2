package main

import (
	"context"
	"flag"
	"fmt"
	"sync"
	"time"
)

// cmdRefresh measures the pure refresh steady-state wall. Refresh is the
// heaviest write path (rotation transaction with the success audit riding it,
// one fsync) and the one never stressed by the single-path walls, so it gets its
// own isolate: each worker logs in once, then chains refresh -> refresh as fast
// as the API allows, holding the newest token in the session mutex so the replay
// defense never fires.
func cmdRefresh(args []string) error {
	fs := flag.NewFlagSet("refresh", flag.ExitOnError)
	bf := newBenchFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := loadPool(bf.pool)
	if err != nil {
		return err
	}
	client := newAPIClient(bf.base)

	hist := &Histogram{}
	errs := &ErrorCounter{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(bf.dur)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < bf.conc; i++ {
		user := p.Entries[i%len(p.Entries)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			chainRefresh(ctx, client, user, hist, errs)
		}()
	}
	wg.Wait()

	p50, p99, p999, n := hist.Report()
	fmt.Printf("  refresh n=%-6d p50=%s p99=%s p999=%s\n", n, p50, p99, p999)
	fmt.Printf("  errors: %s\n", errs.String())
	return nil
}

func chainRefresh(ctx context.Context, client *apiClient, user poolEntry, hist *Histogram, errs *ErrorCounter) {
	pair, err := client.login(ctx, user.Email, user.Password)
	if err != nil {
		fmt.Printf("refresh: login failed: %v\n", err)
		return
	}
	refreshToken := pair.RefreshToken
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		start := time.Now()
		next, err := client.refresh(ctx, refreshToken)
		hist.Add(time.Since(start))
		if err != nil {
			errs.Record(statusOf(err, 0))
			// Replay defense fired or the family died: re-login to get a fresh
			// token, then keep chaining.
			pair, loginErr := client.login(ctx, user.Email, user.Password)
			if loginErr != nil {
				fmt.Printf("refresh: re-login failed: %v\n", loginErr)
				return
			}
			refreshToken = pair.RefreshToken
			continue
		}
		refreshToken = next.RefreshToken
	}
}
