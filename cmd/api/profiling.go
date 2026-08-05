package main

import (
	"net/http"
	"net/http/pprof"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// maxProfileSeconds caps ?seconds on the CPU profile endpoint. WriteTimeout cuts
// the client connection, but the sampling goroutine keeps running past it, so an
// unclamped value would let whoever reaches the endpoint hold CPU sampling well
// beyond the deadline. Cap just under WriteTimeout.
const maxProfileSeconds = int((ServerWriteTimeout - time.Second) / time.Second)

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
	// before writing. Default the sample to 5s so the endpoint works out of the
	// box; ?seconds= is clamped to maxProfileSeconds.
	group.GET("/profile", gin.WrapH(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("seconds") == "" {
			q.Set("seconds", "5")
		} else if seconds, err := strconv.Atoi(q.Get("seconds")); err == nil && seconds > maxProfileSeconds {
			q.Set("seconds", strconv.Itoa(maxProfileSeconds))
		}
		r.URL.RawQuery = q.Encode()
		pprof.Profile(w, r)
	})))
	group.GET("/symbol", gin.WrapF(pprof.Symbol))
	group.GET("/trace", gin.WrapF(pprof.Trace))
	group.GET("/allocs", gin.WrapH(pprof.Handler("allocs")))
	group.GET("/heap", gin.WrapH(pprof.Handler("heap")))
	group.GET("/goroutine", gin.WrapH(pprof.Handler("goroutine")))
	group.GET("/block", gin.WrapH(pprof.Handler("block")))
	group.GET("/mutex", gin.WrapH(pprof.Handler("mutex")))
}
