package redis

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func reviewRESP(r *bufio.Reader) ([]string, error) {
	line, e := r.ReadString('\n')
	if e != nil {
		return nil, e
	}
	n, e := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
	if e != nil {
		return nil, e
	}
	args := make([]string, n)
	for i := range n {
		line, e = r.ReadString('\n')
		if e != nil {
			return nil, e
		}
		size, e := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "$")))
		if e != nil {
			return nil, e
		}
		raw := make([]byte, size+2)
		if _, e = io.ReadFull(r, raw); e != nil {
			return nil, e
		}
		args[i] = string(raw[:size])
	}
	return args, nil
}
func reviewServer(t *testing.T, handler func(net.Conn, []string) bool) string {
	t.Helper()
	var config net.ListenConfig
	ln, e := config.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conns []net.Conn
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				r := bufio.NewReader(conn)
				for {
					args, e := reviewRESP(r)
					if e != nil {
						return
					}
					switch strings.ToUpper(args[0]) {
					case "HELLO":
						_, _ = io.WriteString(conn, "-ERR unknown command 'hello'\r\n")
					case "CLIENT", "SELECT":
						_, _ = io.WriteString(conn, "+OK\r\n")
					case "PING":
						_, _ = io.WriteString(conn, "+PONG\r\n")
					default:
						if !handler(conn, args) {
							return
						}
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return ln.Addr().String()
}
func TestRegressionRedisOptions(t *testing.T) {
	addr := reviewServer(t, func(c net.Conn, _ []string) bool { _, _ = io.WriteString(c, "+OK\r\n"); return true })
	c, _ := New(addr, "", 0)
	defer c.Close()
	o := c.Options()
	t.Logf("effective_MaxRetries=%d ContextTimeoutEnabled=%t", o.MaxRetries, o.ContextTimeoutEnabled)
	if o.MaxRetries != 0 {
		t.Error("New advertises no retries, but zero selects the library default of three retries")
	}
	if !o.ContextTimeoutEnabled {
		t.Error("socket I/O does not use the request deadline")
	}
}
func TestRegressionRedisDeadline(t *testing.T) {
	addr := reviewServer(t, func(c net.Conn, a []string) bool {
		if strings.ToUpper(a[0]) == "GET" {
			time.Sleep(300 * time.Millisecond)
			_, _ = io.WriteString(c, "$-1\r\n")
		} else {
			_, _ = io.WriteString(c, "+OK\r\n")
		}
		return true
	})
	c, _ := New(addr, "", 0)
	defer c.Close()
	if e := c.Ping(context.Background()).Err(); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.Get(ctx, "fixture").Err()
	elapsed := time.Since(start)
	t.Logf("context_budget=20ms elapsed=%s result=%v", elapsed.Round(time.Millisecond), err)
	if elapsed > 150*time.Millisecond {
		t.Error("20ms operation budget was exceeded by Redis socket I/O")
	}
}
func TestRegressionRedisEvictionReplyLoss(t *testing.T) {
	var calls atomic.Int32
	addr := reviewServer(t, func(c net.Conn, a []string) bool {
		if strings.ToUpper(a[0]) == "EVALSHA" {
			if calls.Add(1) == 1 {
				return false
			}
			_, _ = io.WriteString(c, "$0\r\n\r\n")
			return true
		}
		_, _ = fmt.Fprint(c, "+OK\r\n")
		return true
	})
	c, _ := New(addr, "", 0)
	defer c.Close()
	s := Store{Client: c, Keys: NewKeys("review")}
	evicted, err := s.RegisterDevice(context.Background(), 1, "new-device", "ua", "ip", time.Now(), time.Hour, 5)
	t.Logf("EVALSHA_executions=%d returned_evicted=%q error=%v", calls.Load(), evicted, err)
	if calls.Load() > 1 && evicted == "" && err == nil {
		t.Error("lost first eviction reply is silently replaced by a successful replay with no evicted family id")
	}
}
