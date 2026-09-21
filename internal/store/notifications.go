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
func (db *DB) ListPendingNotifications(ctx context.Context, limit int) ([]NotificationOutboxItem, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, application_id, event_type, payload, attempts
		FROM notification_outbox
		WHERE delivered_at IS NULL AND next_attempt_at <= now()
		ORDER BY next_attempt_at
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: listing pending notifications: %w", err)
	}
	defer rows.Close()

	var out []NotificationOutboxItem
	for rows.Next() {
		var item NotificationOutboxItem
		if err := rows.Scan(&item.ID, &item.ApplicationID, &item.EventType, &item.Payload, &item.Attempts); err != nil {
			return nil, fmt.Errorf("store: scanning pending notification: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing pending notifications: %w", err)
	}
	return out, nil
}

// MarkNotificationDelivered records a successful delivery attempt.
func (db *DB) MarkNotificationDelivered(ctx context.Context, id uuid.UUID) error {
	if _, err := db.Pool.Exec(ctx, `UPDATE notification_outbox SET delivered_at = now() WHERE id = $1`, id); err != nil {
		return fmt.Errorf("store: marking notification %s delivered: %w", id, err)
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

// PurgeDeliveredNotifications deletes delivered notification_outbox
// rows older than maxAge -- unlike audit_events, this table has no
// immutability requirement, so the runtime role purges its own rows
// directly (see migration 000017's grant comment) as part of the
// regular internal/worker retention job list, not a separate operator
// command.
func (db *DB) PurgeDeliveredNotifications(ctx context.Context, maxAge time.Duration, limit int) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	tag, err := db.Pool.Exec(ctx, `
		DELETE FROM notification_outbox WHERE id IN (
			SELECT id FROM notification_outbox
			WHERE delivered_at IS NOT NULL AND delivered_at <= $1
			ORDER BY id
			LIMIT $2
		)`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("store: purging delivered notifications: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
