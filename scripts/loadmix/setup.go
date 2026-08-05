package main

import (
	"context"
	"flag"
	"fmt"
	"sync"

	goredis "github.com/redis/go-redis/v9"
)

// cmdSetup registers a pool of users through the real registration flow. The
// send-code endpoint stores the code in Redis before the mailer call, so even
// though SMTP is not configured the code is readable; setup reads it back to
// complete the flow. This is the single deliberate non-black-box step in the
// harness — a user pool has to come from somewhere, and the real flow is the
// most honest source.
func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	bf := newBenchFlags(fs)
	redisAddr := fs.String("redis", defaultRedis, "Redis address for reading verification codes")
	redisPass := fs.String("redis-pass", "change_me", "Redis password")
	redisPrefix := fs.String("redis-prefix", "sastlink", "Redis key prefix")
	password := fs.String("password", "LoadTest@2026", "password for every created account")
	offset := fs.Int("offset", 0, "email index offset (avoids colliding with an earlier pool)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if bf.users <= 0 || bf.users > 10000 {
		return fmt.Errorf("-users must be in (0, 10000]")
	}

	client := newAPIClient(bf.base)
	rdb := goredis.NewClient(&goredis.Options{Addr: *redisAddr, Password: *redisPass})
	defer rdb.Close()
	ctx := context.Background()

	const college = "计算机学院、软件学院、网络空间安全学院"
	entries := make([]poolEntry, 0, bf.users)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 24)

	for i := 0; i < bf.users; i++ {
		idx := i + *offset
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			email := fmt.Sprintf("load%04d@njupt.edu.cn", idx)
			name := fmt.Sprintf("Load Tester %04d", idx)
			if err := client.sendRegisterCode(ctx, email); err != nil {
				fmt.Printf("setup: %s send-code: %v\n", email, err)
				return
			}
			code, err := rdb.Get(ctx, *redisPrefix+":verify:register:"+email).Result()
			if err != nil {
				fmt.Printf("setup: %s read code: %v\n", email, err)
				return
			}
			ticket, err := client.verifyRegisterCode(ctx, email, code)
			if err != nil {
				fmt.Printf("setup: %s verify-code: %v\n", email, err)
				return
			}
			if _, err := client.register(ctx, ticket, email, *password, name,
				fmt.Sprintf("B24%06d", idx), college, "计算机科学与技术"); err != nil {
				fmt.Printf("setup: %s register: %v\n", email, err)
				return
			}
			mu.Lock()
			entries = append(entries, poolEntry{Email: email, Password: *password, Name: name})
			mu.Unlock()
		}(idx)
	}
	wg.Wait()

	if len(entries) < bf.users {
		return fmt.Errorf("registered %d/%d users; raise the bench send-code IP limit if throttled",
			len(entries), bf.users)
	}
	if err := savePool(bf.pool, pool{Entries: entries}); err != nil {
		return err
	}
	fmt.Printf("setup: registered %d users -> %s\n", len(entries), bf.pool)
	return nil
}
