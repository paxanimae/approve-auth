package worker

import (
	"context"
	"time"
)

// Store is the internal/store.DB surface the retention/cleanup jobs
// need (spec section 12), all grantable to the app_runtime role -- see
// this package's doc comment for why audit-log purging isn't here.
type Store interface {
	ExpireTimedOutRequests(ctx context.Context, limit int) (int, error)
	ExpireClaimWindows(ctx context.Context, limit int) (int, error)
	RecordExpiredAuthorizations(ctx context.Context, limit int) (int, error)
	PurgeExpiredClaimEnvelopes(ctx context.Context, limit int) (int, error)
	PurgeExpiredRateLimitBuckets(ctx context.Context, limit int) (int, error)
	PurgeExpiredIdempotencyRecords(ctx context.Context, limit int) (int, error)
	RedactOldClientMetadata(ctx context.Context, maxAge time.Duration, limit int) (int, error)
	RedactOldReturnPaths(ctx context.Context, maxAge time.Duration, limit int) (int, error)
	PurgeResolvedRecords(ctx context.Context, maxAge time.Duration, limit int) (int, error)
	PurgeDeliveredNotifications(ctx context.Context, maxAge time.Duration, limit int) (int, error)
}

// Config is the subset of internal/config.Config these jobs need.
type Config struct {
	ResolvedRequestsRetention time.Duration
	IPAndUserAgentRetention   time.Duration
	ReturnPathsRetention      time.Duration
	NotificationsRetention    time.Duration
	// TickInterval governs how often each job runs. Spec section 12
	// doesn't mandate a specific cadence, only bounded batches -- five
	// minutes (the caller's usual choice) keeps an ordinary backlog (a
	// handful of timeouts/expiries per interval) from ever growing large
	// enough for "bounded" to matter in practice.
	TickInterval time.Duration
}

const (
	batchSize         = 200
	maxBatchesPerTick = 50
)

// Jobs builds the standard retention/cleanup job list against store.
func Jobs(store Store, cfg Config) []Job {
	return []Job{
		{
			Name: "expire_timed_out_requests", Interval: cfg.TickInterval,
			Run: func(ctx context.Context) error {
				return drainBatches(ctx, batchSize, maxBatchesPerTick, store.ExpireTimedOutRequests)
			},
		},
		{
			Name: "expire_claim_windows", Interval: cfg.TickInterval,
			Run: func(ctx context.Context) error {
				return drainBatches(ctx, batchSize, maxBatchesPerTick, store.ExpireClaimWindows)
			},
		},
		{
			Name: "record_expired_authorizations", Interval: cfg.TickInterval,
			Run: func(ctx context.Context) error {
				return drainBatches(ctx, batchSize, maxBatchesPerTick, store.RecordExpiredAuthorizations)
			},
		},
		{
			Name: "purge_expired_claim_envelopes", Interval: cfg.TickInterval,
			Run: func(ctx context.Context) error {
				return drainBatches(ctx, batchSize, maxBatchesPerTick, store.PurgeExpiredClaimEnvelopes)
			},
		},
		{
			Name: "purge_expired_rate_limit_buckets", Interval: cfg.TickInterval,
			Run: func(ctx context.Context) error {
				return drainBatches(ctx, batchSize, maxBatchesPerTick, store.PurgeExpiredRateLimitBuckets)
			},
		},
		{
			Name: "purge_expired_idempotency_records", Interval: cfg.TickInterval,
			Run: func(ctx context.Context) error {
				return drainBatches(ctx, batchSize, maxBatchesPerTick, store.PurgeExpiredIdempotencyRecords)
			},
		},
		{
			Name: "redact_old_client_metadata", Interval: cfg.TickInterval,
			Run: func(ctx context.Context) error {
				return drainBatches(ctx, batchSize, maxBatchesPerTick, func(ctx context.Context, limit int) (int, error) {
					return store.RedactOldClientMetadata(ctx, cfg.IPAndUserAgentRetention, limit)
				})
			},
		},
		{
			Name: "redact_old_return_paths", Interval: cfg.TickInterval,
			Run: func(ctx context.Context) error {
				return drainBatches(ctx, batchSize, maxBatchesPerTick, func(ctx context.Context, limit int) (int, error) {
					return store.RedactOldReturnPaths(ctx, cfg.ReturnPathsRetention, limit)
				})
			},
		},
		{
			Name: "purge_resolved_records", Interval: cfg.TickInterval,
			Run: func(ctx context.Context) error {
				return drainBatches(ctx, batchSize, maxBatchesPerTick, func(ctx context.Context, limit int) (int, error) {
					return store.PurgeResolvedRecords(ctx, cfg.ResolvedRequestsRetention, limit)
				})
			},
		},
		{
			Name: "purge_delivered_notifications", Interval: cfg.TickInterval,
			Run: func(ctx context.Context) error {
				return drainBatches(ctx, batchSize, maxBatchesPerTick, func(ctx context.Context, limit int) (int, error) {
					return store.PurgeDeliveredNotifications(ctx, cfg.NotificationsRetention, limit)
				})
			},
		},
	}
}
