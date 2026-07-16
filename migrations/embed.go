// Package migrations embeds versioned SQL migrations.
package migrations

import "embed"

// FS contains all versioned SQL migrations in this directory.
//
//go:embed *.sql
var FS embed.FS
