package main

import (
	"net/http"
	"net/http/pprof"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// maxProfileSeconds caps ?seconds on the sampling endpoints, just under WriteTimeout.
const maxProfileSeconds = int((ServerWriteTimeout - time.Second) / time.Second)

// defaultProfileSeconds is the sample window used when ?seconds is absent.
const defaultProfileSeconds = 5

// clampSampleSeconds rewrites ?seconds to a value inside (0, maxProfileSeconds].
//
// It must rewrite on every path: net/http/pprof falls back to its own 30s
// default for an absent or unparseable value, which would exceed the ceiling.
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

// registerProfiling mounts the Go runtime profiler under /debug/pprof; the
// endpoints can drive CPU sampling, so production must opt in explicitly.
func registerProfiling(router *gin.Engine) {
	group := router.Group("/debug/pprof")
	group.GET("/", gin.WrapF(pprof.Index))
	group.GET("/cmdline", gin.WrapF(pprof.Cmdline))
	// The stock profile handler samples 30s, beyond WriteTimeout, so clamp it.
	group.GET("/profile", gin.WrapH(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clampSampleSeconds(r)
		pprof.Profile(w, r)
	})))
	group.GET("/symbol", gin.WrapF(pprof.Symbol))
	// Trace needs the same clamp as /profile to bound its sample window.
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
