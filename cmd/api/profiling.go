package main

import (
	"net/http"
	"net/http/pprof"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// maxProfileSeconds caps ?seconds on the sampling endpoints. WriteTimeout cuts
// the client connection, but the sampling goroutine keeps running past it, so an
// unclamped value would let whoever reaches the endpoint hold CPU sampling well
// beyond the deadline. Cap just under WriteTimeout.
const maxProfileSeconds = int((ServerWriteTimeout - time.Second) / time.Second)

// defaultProfileSeconds is the sample window used when ?seconds is absent. The
// stock handlers default to 30s, which WriteTimeout would cut before they write
// anything, so the endpoints would never work out of the box.
const defaultProfileSeconds = 5

// clampSampleSeconds rewrites ?seconds to a value inside (0, maxProfileSeconds].
//
// It must rewrite on every path, not just the too-large one: net/http/pprof
// treats an absent, unparseable or non-positive ?seconds as "use my 30s
// default", so leaving a garbage value in place (?seconds=abc, ?seconds=-1)
// silently buys the caller a 30s sample — longer than the ceiling this exists to
// enforce. Parse it here and always write back something valid.
func clampSampleSeconds(r *http.Request) {
	query := r.URL.Query()
	seconds, err := strconv.Atoi(query.Get("seconds"))
	switch {
	case err != nil || seconds <= 0:
		seconds = defaultProfileSeconds
	case seconds > maxProfileSeconds:
		seconds = maxProfileSeconds
	}
	query.Set("seconds", strconv.Itoa(seconds))
	r.URL.RawQuery = query.Encode()
}

// registerProfiling mounts the Go runtime profiler under /debug/pprof. main.go
// calls it only in development or when PPROF_ENABLED is set: the endpoints
// expose heap and goroutine dumps and can be used to drive CPU sampling, so a
// production deployment must opt in explicitly.
func registerProfiling(router *gin.Engine) {
	group := router.Group("/debug/pprof")
	group.GET("/", gin.WrapF(pprof.Index))
	group.GET("/cmdline", gin.WrapF(pprof.Cmdline))
	// The HTTP server's WriteTimeout (10s) cuts the response if the handler
	// writes nothing for that long, and the stock profile handler samples 30s
	// before writing, so both sampling endpoints go through clampSampleSeconds.
	group.GET("/profile", gin.WrapH(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clampSampleSeconds(r)
		pprof.Profile(w, r)
	})))
	group.GET("/symbol", gin.WrapF(pprof.Symbol))
	// Trace needs the same clamp as /profile, not less: it takes ?seconds through
	// the same "any value goes" parsing, and an hour-long runtime trace is more
	// expensive than an hour-long CPU profile because the tracer writes an event
	// stream for the whole window rather than sampling it.
	group.GET("/trace", gin.WrapH(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clampSampleSeconds(r)
		pprof.Trace(w, r)
	})))
	group.GET("/allocs", gin.WrapH(pprof.Handler("allocs")))
	group.GET("/heap", gin.WrapH(pprof.Handler("heap")))
	group.GET("/goroutine", gin.WrapH(pprof.Handler("goroutine")))
	group.GET("/block", gin.WrapH(pprof.Handler("block")))
	group.GET("/mutex", gin.WrapH(pprof.Handler("mutex")))
}
