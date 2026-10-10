package metrics

import (
	"time"

	"gorm.io/gorm"
)

// GormPlugin exposes GORM statement latency as gorm_query_duration_seconds /
// gorm_slow_query_total. It registers before/after callbacks on every
// statement processor (query, create, update, delete, raw, row) through the
// standard gorm.Plugin interface, so no repository call site changes.
//
// Anchor names differ per processor: only the mutation processors
// (create/update/delete) carry the gorm:begin_transaction /
// gorm:commit_or_rollback_transaction pair, and registering against a name a
// processor does not have is silently ignored in sorting — the callback would
// land at the end of the chain and measure nothing. So each processor anchors
// on the callbacks that gorm's own setup installs for it. gorm's processor and
// callback types are unexported, hence the chain-style registration below.
//
// Transaction duration is deliberately not measured here: a transaction spans
// many statements and the callback chain carries no cross-statement state (the
// ConnPool wrap that prepared_stmt.go uses is a far bigger change than the
// signal is worth). Pool wait plus statement p99 already attribute lock
// contention. Two measurement caveats: raw/row row-iteration (Scan after
// Execute) is outside the timed span — the same blind spot gorm's own slow
// log has — and a gorm upgrade that renames an anchor callback silently sorts
// these to the chain tail (the metric still fires, around a shorter span), so
// a gorm bump should re-check the callback names against RegisterDefaultCallbacks.
const (
	// gormSlowThreshold is the bar for gorm_slow_query_total. The GORM logger
	// uses 200ms for its own slow log; the metric threshold is a little wider
	// because a 1c1g box runs everything slower than a laptop.
	gormSlowThreshold = 500 * time.Millisecond

	gormStartKey = "metrics:statement_start"
)

// GormPluginName is the plugin's registration name.
const GormPluginName = "sast_metrics"

type gormPlugin struct{}

// NewGormPlugin returns the statement-metrics plugin for db.Use.
func NewGormPlugin() gorm.Plugin { return gormPlugin{} }

func (gormPlugin) Name() string { return GormPluginName }

func (gormPlugin) Initialize(db *gorm.DB) error {
	begin := func(tx *gorm.DB) { tx.InstanceSet(gormStartKey, time.Now()) }
	end := func(op string) func(*gorm.DB) {
		return func(tx *gorm.DB) {
			if start, ok := tx.InstanceGet(gormStartKey); ok {
				if beginAt, valid := start.(time.Time); valid {
					GormQuery(op, time.Since(beginAt), gormSlowThreshold)
				}
			}
		}
	}

	// Per-processor registration; the unexported *processor type makes a
	// table-driven loop impossible across packages.
	query := db.Callback().Query()
	if err := query.Before("gorm:query").Register("metrics:query_begin", begin); err != nil {
		return err
	}
	if err := query.After("gorm:after_query").Register("metrics:query_end", end(GormOpQuery)); err != nil {
		return err
	}
	raw := db.Callback().Raw()
	if err := raw.Before("gorm:raw").Register("metrics:raw_begin", begin); err != nil {
		return err
	}
	if err := raw.After("gorm:raw").Register("metrics:raw_end", end(GormOpRaw)); err != nil {
		return err
	}
	row := db.Callback().Row()
	if err := row.Before("gorm:row").Register("metrics:row_begin", begin); err != nil {
		return err
	}
	if err := row.After("gorm:row").Register("metrics:row_end", end(GormOpRaw)); err != nil {
		return err
	}
	create := db.Callback().Create()
	if err := create.Before("gorm:begin_transaction").Register("metrics:create_begin", begin); err != nil {
		return err
	}
	if err := create.After("gorm:commit_or_rollback_transaction").Register("metrics:create_end", end(GormOpExec)); err != nil {
		return err
	}
	update := db.Callback().Update()
	if err := update.Before("gorm:begin_transaction").Register("metrics:update_begin", begin); err != nil {
		return err
	}
	if err := update.After("gorm:commit_or_rollback_transaction").Register("metrics:update_end", end(GormOpExec)); err != nil {
		return err
	}
	del := db.Callback().Delete()
	if err := del.Before("gorm:begin_transaction").Register("metrics:delete_begin", begin); err != nil {
		return err
	}
	if err := del.After("gorm:commit_or_rollback_transaction").Register("metrics:delete_end", end(GormOpExec)); err != nil {
		return err
	}
	return nil
}
