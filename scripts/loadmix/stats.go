package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Histogram accumulates request latencies and reports percentiles. Fixed and
// simple on purpose: a bench tool does not need a histogram library, and sorting
// tens of thousands of time.Duration values per path at report time is cheap.
type Histogram struct {
	mu    sync.Mutex
	times []time.Duration
}

func (h *Histogram) Add(d time.Duration) {
	h.mu.Lock()
	h.times = append(h.times, d)
	h.mu.Unlock()
}

func (h *Histogram) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.times)
}

// Report returns p50/p99/p999 and the sample count. A histogram with no samples
// reports zeroes; callers should print the count so a zero is distinguishable
// from a genuinely instant path.
func (h *Histogram) Report() (p50, p99, p999 time.Duration, n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n = len(h.times)
	if n == 0 {
		return 0, 0, 0, 0
	}
	sort.Slice(h.times, func(i, j int) bool { return h.times[i] < h.times[j] })
	pct := func(p float64) time.Duration { return h.times[int(float64(n-1)*p)] }
	return pct(0.50), pct(0.99), pct(0.999), n
}

// ErrorCounter counts non-2xx responses per status code.
type ErrorCounter struct {
	mu    sync.Mutex
	by    map[int]int
	total int
}

func (e *ErrorCounter) Record(status int) {
	e.mu.Lock()
	if e.by == nil {
		e.by = make(map[int]int)
	}
	e.by[status]++
	e.total++
	e.mu.Unlock()
}

func (e *ErrorCounter) Snapshot() (map[int]int, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[int]int, len(e.by))
	for k, v := range e.by {
		out[k] = v
	}
	return out, e.total
}

func (e *ErrorCounter) String() string {
	by, total := e.Snapshot()
	if total == 0 {
		return "no errors"
	}
	var parts []string
	for code, n := range by {
		parts = append(parts, fmt.Sprintf("%d:%d", code, n))
	}
	return fmt.Sprintf("%d errors (%s)", total, join(parts, " "))
}

func join(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}
