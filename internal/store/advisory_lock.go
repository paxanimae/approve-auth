package store

import (
	"context"
	"fmt"
	"hash/fnv"
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
func (db *DB) WithAdvisoryLock(ctx context.Context, key string, fn func(ctx context.Context) error) (ran bool, err error) {
	conn, err := db.Pool.Acquire(ctx)
	if err != nil {
		return false, fmt.Errorf("store: acquiring connection for advisory lock %q: %w", key, err)
	}
	defer conn.Release()

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
