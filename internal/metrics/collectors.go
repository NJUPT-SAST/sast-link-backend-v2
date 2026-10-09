package metrics

import (
	"database/sql"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Pool-state collectors. Unlike the vecs above, these read live snapshots
// (sql.DBStats, go-redis pool stats) rather than counting events, so they are
// custom Collectors. The data source is injected at startup from cmd/api
// through SetDBPoolSource / SetRedisPoolSource; until injection the collectors
// simply emit nothing on /metrics (a Collect that sends no metric is legal),
// which keeps the package importable — and testable — without a live store.

// DBPoolSnapshot is the subset of sql.DBStats worth scraping. WaitCount and
// WaitDuration are the pool-saturation evidence: a non-zero, growing wait
// means requests are queueing for one of the maxOpenConns connections while
// every individual query still looks fast.
type DBPoolSnapshot struct {
	MaxOpenConnections int
	OpenConnections    int
	InUse              int
	Idle               int
	WaitCount          int64
	WaitDuration       time.Duration
}

// RedisPoolSnapshot mirrors go-redis pool.Stats' counters. Timeouts are the
// fail-open store telling us it shed load; hits/misses ratio shows whether the
// MinIdle floor is sized for the working set.
type RedisPoolSnapshot struct {
	Hits       uint64
	Misses     uint64
	Timeouts   uint64
	TotalConns uint64
	IdleConns  uint64
}

var (
	dbPoolSource    atomic.Pointer[func() DBPoolSnapshot]
	redisPoolSource atomic.Pointer[func() RedisPoolSnapshot]
)

// SetDBPoolSource injects the database pool snapshot provider. A nil fn
// detaches it (Store(nil), not a pointer to a nil function — dereferencing
// that panics on every scrape).
func SetDBPoolSource(fn func() DBPoolSnapshot) {
	if fn == nil {
		dbPoolSource.Store(nil)
		return
	}
	dbPoolSource.Store(&fn)
}

// SetRedisPoolSource injects the Redis pool snapshot provider.
func SetRedisPoolSource(fn func() RedisPoolSnapshot) {
	if fn == nil {
		redisPoolSource.Store(nil)
		return
	}
	redisPoolSource.Store(&fn)
}

type dbPoolCollector struct {
	inUse        *prometheus.Desc
	open         *prometheus.Desc
	idle         *prometheus.Desc
	maxOpen      *prometheus.Desc
	waitCount    *prometheus.Desc
	waitDuration *prometheus.Desc
}

func newDBPoolCollector() *dbPoolCollector {
	labels := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(name, help, nil, nil)
	}
	return &dbPoolCollector{
		inUse:        labels("db_pool_in_use", "Connections currently checked out of the PostgreSQL pool."),
		open:         labels("db_pool_open", "Connections currently open (in use + idle)."),
		idle:         labels("db_pool_idle", "Idle connections in the PostgreSQL pool."),
		maxOpen:      labels("db_pool_max_open", "The pool's configured maximum open connections."),
		waitCount:    labels("db_pool_wait_count", "Cumulative count of requests that waited for a pool connection."),
		waitDuration: labels("db_pool_wait_duration_seconds", "Cumulative time requests spent waiting for a pool connection."),
	}
}

func (c *dbPoolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.inUse
	ch <- c.open
	ch <- c.idle
	ch <- c.maxOpen
	ch <- c.waitCount
	ch <- c.waitDuration
}

func (c *dbPoolCollector) Collect(ch chan<- prometheus.Metric) {
	fn := dbPoolSource.Load()
	if fn == nil {
		return
	}
	s := (*fn)()
	ch <- prometheus.MustNewConstMetric(c.inUse, prometheus.GaugeValue, float64(s.InUse))
	ch <- prometheus.MustNewConstMetric(c.open, prometheus.GaugeValue, float64(s.OpenConnections))
	ch <- prometheus.MustNewConstMetric(c.idle, prometheus.GaugeValue, float64(s.Idle))
	ch <- prometheus.MustNewConstMetric(c.maxOpen, prometheus.GaugeValue, float64(s.MaxOpenConnections))
	ch <- prometheus.MustNewConstMetric(c.waitCount, prometheus.CounterValue, float64(s.WaitCount))
	ch <- prometheus.MustNewConstMetric(c.waitDuration, prometheus.CounterValue, s.WaitDuration.Seconds())
}

type redisPoolCollector struct {
	hits     *prometheus.Desc
	misses   *prometheus.Desc
	timeouts *prometheus.Desc
	total    *prometheus.Desc
	idle     *prometheus.Desc
}

func newRedisPoolCollector() *redisPoolCollector {
	labels := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(name, help, nil, nil)
	}
	return &redisPoolCollector{
		hits:     labels("redis_pool_hits", "Cumulative go-redis pool hits (connection reused without waiting)."),
		misses:   labels("redis_pool_misses", "Cumulative go-redis pool misses (no idle connection readily available)."),
		timeouts: labels("redis_pool_timeouts", "Cumulative go-redis pool waits that exceeded PoolTimeout. Each one is a request the fail-open design absorbed."),
		total:    labels("redis_pool_total_conns", "Connections currently in the go-redis pool."),
		idle:     labels("redis_pool_idle_conns", "Idle connections in the go-redis pool."),
	}
}

func (c *redisPoolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.hits
	ch <- c.misses
	ch <- c.timeouts
	ch <- c.total
	ch <- c.idle
}

func (c *redisPoolCollector) Collect(ch chan<- prometheus.Metric) {
	fn := redisPoolSource.Load()
	if fn == nil {
		return
	}
	s := (*fn)()
	ch <- prometheus.MustNewConstMetric(c.hits, prometheus.CounterValue, float64(s.Hits))
	ch <- prometheus.MustNewConstMetric(c.misses, prometheus.CounterValue, float64(s.Misses))
	ch <- prometheus.MustNewConstMetric(c.timeouts, prometheus.CounterValue, float64(s.Timeouts))
	ch <- prometheus.MustNewConstMetric(c.total, prometheus.GaugeValue, float64(s.TotalConns))
	ch <- prometheus.MustNewConstMetric(c.idle, prometheus.GaugeValue, float64(s.IdleConns))
}

// SnapshotDBPool adapts sql.DBStats onto DBPoolSnapshot.
func SnapshotDBPool(s sql.DBStats) DBPoolSnapshot {
	return DBPoolSnapshot{
		MaxOpenConnections: s.MaxOpenConnections,
		OpenConnections:    s.OpenConnections,
		InUse:              s.InUse,
		Idle:               s.Idle,
		WaitCount:          s.WaitCount,
		WaitDuration:       s.WaitDuration,
	}
}
