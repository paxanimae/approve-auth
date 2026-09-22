package store

import (
	"context"
	"fmt"
	"hash/fnv"

	"github.com/jackc/pgx/v5"
)

// WithAdvisoryLock runs fn only if it acquires the named Postgres
// advisory lock, so at most one replica performs the same named
// operation at a time (spec section 2: "Cleanup jobs use advisory locks
// and bounded batches"). ran is false if another replica already holds
// the lock; fn was not called in that case. Uses a session-level lock on
// a dedicated connection (not a transaction-scoped one) so it still
// coordinates correctly even though fn itself may run several of its
// own separate transactions; the lock and its connection are always
// released before this returns, regardless of fn's outcome.
//
// The dedicated connection is opened directly (pgx.ConnectConfig), never
// drawn from db.Pool: internal/worker's Scheduler starts every job's
// first run concurrently on startup, and each one holds this connection
// for as long as fn runs, which itself acquires its own connection(s)
// from db.Pool for its real work. Drawing the lock's connection from
// that same pool let all of a small pool's connections fill up with
// nothing but idle lock-holders before any job's fn got a connection to
// do anything with -- a guaranteed deadlock once job count met or
// exceeded the pool's size (pgxpool defaults MaxConns to
// max(4, runtime.NumCPU()), so this reliably self-deadlocked on any
// host with 4 or fewer visible CPUs). A lock connection outside the pool
// can never compete with fn for the pool's capacity.
func (db *DB) WithAdvisoryLock(ctx context.Context, key string, fn func(ctx context.Context) error) (ran bool, err error) {
	conn, err := pgx.ConnectConfig(ctx, db.Pool.Config().ConnConfig.Copy())
	if err != nil {
		return false, fmt.Errorf("store: opening dedicated connection for advisory lock %q: %w", key, err)
	}
	defer func() { _ = conn.Close(ctx) }()

	lockKey := advisoryLockKey(key)
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&locked); err != nil {
		return false, fmt.Errorf("store: acquiring advisory lock %q: %w", key, err)
	}
	if !locked {
		return false, nil
	}
	defer func() {
		_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, lockKey)
	}()

	return true, fn(ctx)
}

// advisoryLockKey derives a stable int64 key from a human-readable job
// name -- pg_try_advisory_lock takes a bigint, not a string.
func advisoryLockKey(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int64(h.Sum64())
}
