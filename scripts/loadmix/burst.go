package main

import (
	"context"
	"flag"
	"fmt"
	"sync"
	"time"
)

// cmdBurst measures the login-rush case that single-path walls miss: a burst of
// simultaneous logins (no think time) against a background of steady profile
// readers, so the report carries both the login p99 *and* how much the read path
// degrades while the KDF serializes on the one core.
func cmdBurst(args []string) error {
	fs := flag.NewFlagSet("burst", flag.ExitOnError)
	base := fs.String("base", defaultBase, "API base URL")
	pool := fs.String("pool", defaultPool, "user pool file")
	loginConc := fs.Int("login", 100, "concurrent login workers")
	readConc := fs.Int("read", 50, "concurrent background read workers")
	dur := fs.Int("duration", 60, "seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := loadPool(*pool)
	if err != nil {
		return err
	}
	client := newAPIClient(*base)

	loginHist, readHist := &Histogram{}, &Histogram{}
	loginErrs, readErrs := &ErrorCounter{}, &ErrorCounter{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*dur)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	// Background readers: hold one session each, loop profile reads, re-login on
	// access-token expiry. They are the "normal traffic" the login rush starves.
	for i := 0; i < *readConc; i++ {
		user := p.Entries[i%len(p.Entries)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			pair, err := client.login(ctx, user.Email, user.Password)
			if err != nil {
				fmt.Printf("burst: reader login failed: %v\n", err)
				return
			}
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				start := time.Now()
				status, err := client.profile(ctx, pair.AccessToken)
				record(readHist, start, readErrs, status, err)
				if status == httpStatusUnauthorized {
					pair, err = client.login(ctx, user.Email, user.Password)
					if err != nil {
						return
					}
				}
			}
		}()
	}
	// Foreground login workers: back-to-back logins, the rush itself.
	for i := 0; i < *loginConc; i++ {
		user := p.Entries[i%len(p.Entries)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				start := time.Now()
				_, err := client.login(ctx, user.Email, user.Password)
				record(loginHist, start, loginErrs, statusOf(err, 200), err)
			}
		}()
	}
	wg.Wait()

	l50, l99, l999, ln := loginHist.Report()
	r50, r99, r999, rn := readHist.Report()
	fmt.Printf("  login  n=%-6d p50=%s p99=%s p999=%s\n", ln, l50, l99, l999)
	fmt.Printf("  profile n=%-6d p50=%s p99=%s p999=%s\n", rn, r50, r99, r999)
	fmt.Printf("  login errors: %s\n", loginErrs.String())
	fmt.Printf("  profile errors: %s\n", readErrs.String())
	return nil
}

const httpStatusUnauthorized = 401
