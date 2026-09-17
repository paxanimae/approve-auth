package store

import "context"

// SchemaReady reports whether migrations have been applied. cmd/server
// checks this at startup instead of running migrations itself: its own
// DATABASE_URL is the least-privilege app_runtime role, which cannot
// execute migration 000012's CREATE ROLE statements against a fresh
// database. Migrations are a separate, privileged, one-off step (spec
// section 13) -- see cmd/admin's migrate-up/migrate-down subcommands.
func (db *DB) SchemaReady(ctx context.Context) (bool, error) {
	var name *string
	err := db.Pool.QueryRow(ctx, `SELECT to_regclass('public.applications')::text`).Scan(&name)
	if err != nil {
		return false, err
	}
	return name != nil, nil
}
