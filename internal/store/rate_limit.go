package store

import (
	"context"
	"fmt"
	"time"
)

// IncrementRateLimit atomically increments the counter for bucketKey
// within [windowStart, windowStart+windowTTL) and returns the count
// after incrementing -- the caller compares that against its configured
// limit (spec section 11, control 6). windowStart is the caller's
// choice of bucketing (e.g. truncated to the hour for an hourly limit),
// so the same bucketKey never collides across different callers' window
// granularities.
func (db *DB) IncrementRateLimit(ctx context.Context, bucketKey string, windowStart time.Time, windowTTL time.Duration) (int, error) {
	var count int
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO rate_limit_buckets (bucket_key, window_start, count, expires_at)
		VALUES ($1, $2, 1, $3)
		ON CONFLICT (bucket_key, window_start) DO UPDATE SET count = rate_limit_buckets.count + 1
		RETURNING count`,
		bucketKey, windowStart, windowStart.Add(windowTTL),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store: incrementing rate limit bucket %q: %w", bucketKey, err)
	}
	return count, nil
}
