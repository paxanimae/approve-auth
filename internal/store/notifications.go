package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// EnqueueNotification writes one durable notification_outbox row (spec-
// adjacent design, not spec-mandated -- see internal/notify's own doc
// comment). Its own transaction, separate from whatever created the
// triggering event: notifications are best-effort, not part of the
// audit-immutable/transactionally-consistent core the rest of this
// package protects, so callers treat a failure here as advisory (log
// and continue), the same way internal/authz treats TouchLastSeen.
func (db *DB) EnqueueNotification(ctx context.Context, applicationID uuid.UUID, eventType string, payload []byte) error {
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO notification_outbox (application_id, event_type, payload)
		VALUES ($1, $2, $3)`, applicationID, eventType, payload); err != nil {
		return fmt.Errorf("store: enqueuing notification: %w", err)
	}
	return nil
}

// ListPendingNotifications returns up to limit rows due for a delivery
// attempt, oldest-due first. No row locking: the delivery job that
// calls this always runs under worker.Scheduler's own per-job advisory
// lock, so at most one process is ever calling this at a time -- the
// same reasoning PurgeExpiredClaimEnvelopes and friends already rely on.
// giveup_at IS NULL excludes rows the job has stopped retrying
// (endpoint-review.md F4) -- those are terminal, not merely pending.
func (db *DB) ListPendingNotifications(ctx context.Context, limit int) ([]NotificationOutboxItem, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, application_id, event_type, payload, attempts, created_at, email_delivered_at, webhook_delivered_at
		FROM notification_outbox
		WHERE delivered_at IS NULL AND giveup_at IS NULL AND next_attempt_at <= now()
		ORDER BY next_attempt_at
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: listing pending notifications: %w", err)
	}
	defer rows.Close()

	var out []NotificationOutboxItem
	for rows.Next() {
		var item NotificationOutboxItem
		if err := rows.Scan(&item.ID, &item.ApplicationID, &item.EventType, &item.Payload, &item.Attempts, &item.CreatedAt, &item.EmailDeliveredAt, &item.WebhookDeliveredAt); err != nil {
			return nil, fmt.Errorf("store: scanning pending notification: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing pending notifications: %w", err)
	}
	return out, nil
}

// MarkNotificationDelivered records that every channel this row needed
// has now succeeded.
func (db *DB) MarkNotificationDelivered(ctx context.Context, id uuid.UUID) error {
	if _, err := db.Pool.Exec(ctx, `UPDATE notification_outbox SET delivered_at = now() WHERE id = $1`, id); err != nil {
		return fmt.Errorf("store: marking notification %s delivered: %w", id, err)
	}
	return nil
}

// MarkNotificationChannelDelivered records that one specific channel
// (email or webhook) succeeded on this attempt, independent of the
// other (endpoint-review.md F4) -- idempotent, since a channel already
// marked delivered is simply overwritten with the same effect. This
// does not set delivered_at itself; the caller (internal/notify's
// delivery job) calls MarkNotificationDelivered separately once every
// channel the row needs has succeeded.
func (db *DB) MarkNotificationChannelDelivered(ctx context.Context, id uuid.UUID, channel string) error {
	var column string
	switch channel {
	case "email":
		column = "email_delivered_at"
	case "webhook":
		column = "webhook_delivered_at"
	default:
		return fmt.Errorf("store: marking notification %s channel delivered: unknown channel %q", id, channel)
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE notification_outbox SET `+column+` = now() WHERE id = $1`, id); err != nil {
		return fmt.Errorf("store: marking notification %s channel %q delivered: %w", id, channel, err)
	}
	return nil
}

// MarkNotificationFailed records a failed delivery attempt, scheduling
// the next one at nextAttemptAt (internal/notify's own backoff schedule).
func (db *DB) MarkNotificationFailed(ctx context.Context, id uuid.UUID, nextAttemptAt time.Time, lastError string) error {
	if _, err := db.Pool.Exec(ctx, `
		UPDATE notification_outbox SET attempts = attempts + 1, next_attempt_at = $2, last_error = $3
		WHERE id = $1`, id, nextAttemptAt, lastError); err != nil {
		return fmt.Errorf("store: marking notification %s failed: %w", id, err)
	}
	return nil
}

// GiveUpOnNotification stops retrying a row that has exceeded its own
// maximum retry age or attempt count (endpoint-review.md F4: "apply
// maximum retry age, queue size, and terminal-failure handling").
// delivered_at is left NULL -- this was never actually delivered -- but
// giveup_at excludes it from ListPendingNotifications going forward,
// and the payload is replaced with an empty object so a permanently
// stuck row doesn't retain its content indefinitely ("remove sensitive
// payload content from expired or failed events").
func (db *DB) GiveUpOnNotification(ctx context.Context, id uuid.UUID, reason string) error {
	if _, err := db.Pool.Exec(ctx, `
		UPDATE notification_outbox SET giveup_at = now(), last_error = $2, payload = '{}'::jsonb
		WHERE id = $1`, id, reason); err != nil {
		return fmt.Errorf("store: giving up on notification %s: %w", id, err)
	}
	return nil
}

// PurgeDeliveredNotifications deletes delivered or given-up
// notification_outbox rows older than maxAge -- unlike audit_events,
// this table has no immutability requirement, so the runtime role
// purges its own rows directly (see migration 000017's grant comment)
// as part of the regular internal/worker retention job list, not a
// separate operator command. A given-up row (endpoint-review.md F4) is
// as terminal as a delivered one and must not accumulate forever
// either, even though its payload was already redacted at giveup time.
func (db *DB) PurgeDeliveredNotifications(ctx context.Context, maxAge time.Duration, limit int) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	tag, err := db.Pool.Exec(ctx, `
		DELETE FROM notification_outbox WHERE id IN (
			SELECT id FROM notification_outbox
			WHERE coalesce(delivered_at, giveup_at) IS NOT NULL AND coalesce(delivered_at, giveup_at) <= $1
			ORDER BY id
			LIMIT $2
		)`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("store: purging delivered notifications: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
