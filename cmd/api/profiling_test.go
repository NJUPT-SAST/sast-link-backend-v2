package main

import (
	"context"
	"net/http/httptest"
	"strconv"
	"testing"
)

// clampSampleSeconds must never leave a value net/http/pprof would read as "use
// my 30s default": an absent, unparseable or non-positive ?seconds all take that
// path, so each has to come back rewritten. maxProfileSeconds is the ceiling the
// server WriteTimeout imposes, and /trace shares the clamp with /profile because
// an unbounded runtime trace is the more expensive of the two.
func TestClampSampleSeconds(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  int
	}{
		{name: "absent", query: "", want: defaultProfileSeconds},
		{name: "empty", query: "seconds=", want: defaultProfileSeconds},
		{name: "unparseable", query: "seconds=abc", want: defaultProfileSeconds},
		{name: "negative", query: "seconds=-1", want: defaultProfileSeconds},
		{name: "zero", query: "seconds=0", want: defaultProfileSeconds},
		{name: "in range", query: "seconds=3", want: 3},
		{name: "at ceiling", query: "seconds=" + strconv.Itoa(maxProfileSeconds), want: maxProfileSeconds},
		{name: "over ceiling", query: "seconds=3600", want: maxProfileSeconds},
		{name: "overflow", query: "seconds=99999999999999999999", want: defaultProfileSeconds},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(context.Background(), "GET", "/debug/pprof/profile?"+test.query, nil)
			clampSampleSeconds(request)
			got, err := strconv.Atoi(request.URL.Query().Get("seconds"))
			if err != nil {
				t.Fatalf("seconds = %q, want a parseable integer", request.URL.Query().Get("seconds"))
			}
			if got != test.want {
				t.Fatalf("seconds = %d, want %d", got, test.want)
			}
		})
	}
}

// The clamp rewrites only ?seconds; a caller's other parameters must survive so
// debugging keeps working (pprof reads ?debug and ?gc on other endpoints).
func TestClampSampleSecondsPreservesOtherParams(t *testing.T) {
	request := httptest.NewRequestWithContext(context.Background(), "GET", "/debug/pprof/trace?seconds=9999&debug=1", nil)
	clampSampleSeconds(request)
	query := request.URL.Query()
	if got := query.Get("seconds"); got != strconv.Itoa(maxProfileSeconds) {
		t.Fatalf("seconds = %q, want %d", got, maxProfileSeconds)
	}
	if got := query.Get("debug"); got != "1" {
		t.Fatalf("debug = %q, want 1", got)
	}
}

// The ceiling has to stay under the server WriteTimeout, or the sampling
// goroutine outlives the connection it was started for.
func TestMaxProfileSecondsStaysUnderWriteTimeout(t *testing.T) {
	if maxProfileSeconds <= 0 {
		t.Fatalf("maxProfileSeconds = %d, want positive", maxProfileSeconds)
	}
	if float64(maxProfileSeconds) >= ServerWriteTimeout.Seconds() {
		t.Fatalf("maxProfileSeconds = %d, want less than WriteTimeout %s", maxProfileSeconds, ServerWriteTimeout)
	}
	if defaultProfileSeconds > maxProfileSeconds {
		t.Fatalf("defaultProfileSeconds = %d, want <= maxProfileSeconds %d", defaultProfileSeconds, maxProfileSeconds)
	}
}
