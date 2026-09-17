// Package migrations embeds the SQL migration files so the service binary
// is self-contained: no migrations/ directory needs to exist at runtime.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
