package store

import (
	"context"
	"fmt"
	"time"
)

// OverviewCounts backs GET /api/v1/overview (spec section 9): "pending,
// active, expiring within 7 days, revoked/expired recently."
type OverviewCounts struct {
	Pending                int64
	Active                 int64
	ExpiringSoon           int64
	RevokedOrExpiredRecent int64
}

// GetOverviewCounts runs the four counts in one round trip.
// expiringSoonWindow and recentWindow are config-driven (spec section
// 14's EXPIRING_SOON_WINDOW and, for "recently," a fixed lookback --
// callers pass what they consider recent). Both bounds are computed
// against the database's own now() rather than the Go process's clock
// (spec section 7: "derive effective expiry from database time"); the
// duration is passed as a float of seconds and turned into an interval
// in SQL, since pgx has no direct time.Duration<->interval mapping.
func (db *DB) GetOverviewCounts(ctx context.Context, expiringSoonWindow, recentWindow time.Duration) (OverviewCounts, error) {
	var c OverviewCounts
	err := db.Pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM approval_requests WHERE status = 'pending'),
			(SELECT count(*) FROM authorizations WHERE revoked_at IS NULL AND activated_at IS NOT NULL AND expires_at > now()),
			(SELECT count(*) FROM authorizations WHERE revoked_at IS NULL AND activated_at IS NOT NULL AND expires_at > now() AND expires_at <= now() + ($1 * interval '1 second')),
			(SELECT count(*) FROM authorizations WHERE (revoked_at IS NOT NULL AND revoked_at > now() - ($2 * interval '1 second')) OR (revoked_at IS NULL AND expires_at <= now() AND expires_at > now() - ($2 * interval '1 second')))`,
		expiringSoonWindow.Seconds(), recentWindow.Seconds(),
	).Scan(&c.Pending, &c.Active, &c.ExpiringSoon, &c.RevokedOrExpiredRecent)
	if err != nil {
		return OverviewCounts{}, fmt.Errorf("store: getting overview counts: %w", err)
	}
	return c, nil
}
