package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ListAuditEventsParams backs GET /audit-events (spec section 9 and 10:
// "actor, action, application, date range, and outcome filters"). A nil/
// zero-value field means "don't filter on this."
type ListAuditEventsParams struct {
	ApplicationID  *uuid.UUID
	ActorSubject   string
	Action         string
	Outcome        string
	OccurredAfter  time.Time
	OccurredBefore time.Time
	Limit          int
}

func scanAuditEvent(row scanner) (AuditEvent, error) {
	var e AuditEvent
	err := row.Scan(
		&e.ID, &e.OccurredAt, &e.ActorType, &e.ActorSubject, &e.Action,
		&e.ApplicationID, &e.RequestID, &e.AuthorizationID, &e.CorrelationID,
		&e.SourceIP, &e.Reason, &e.RedactedBefore, &e.RedactedAfter, &e.Outcome,
	)
	return e, err
}

const auditEventColumns = `id, occurred_at, actor_type, actor_subject, action, application_id, request_id, authorization_id, correlation_id, source_ip, reason, redacted_before, redacted_after, outcome`

// ListAuditEvents is a first-pass listing: newest first, simple limit-
// bounded like ListApprovalRequests/ListAuthorizations rather than the
// full cursor-paginated listing spec section 10 describes -- that's
// follow-on work.
func (db *DB) ListAuditEvents(ctx context.Context, p ListAuditEventsParams) ([]AuditEvent, error) {
	limit := p.Limit
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	rows, err := db.Pool.Query(ctx, `
		SELECT `+auditEventColumns+`
		FROM audit_events
		WHERE ($1::uuid IS NULL OR application_id = $1)
		  AND ($2::text = '' OR actor_subject = $2)
		  AND ($3::text = '' OR action = $3)
		  AND ($4::text = '' OR outcome = $4)
		  AND ($5::timestamptz IS NULL OR occurred_at >= $5)
		  AND ($6::timestamptz IS NULL OR occurred_at <= $6)
		ORDER BY occurred_at DESC, id DESC
		LIMIT $7`,
		p.ApplicationID, p.ActorSubject, p.Action, p.Outcome,
		nullableTime(p.OccurredAfter), nullableTime(p.OccurredBefore), limit)
	if err != nil {
		return nil, fmt.Errorf("store: listing audit events: %w", err)
	}
	defer rows.Close()

	var out []AuditEvent
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning audit event: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing audit events: %w", err)
	}
	return out, nil
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// RecordAuditEvent writes one standalone audit event not otherwise tied
// to a row mutation -- currently just the audit export itself (spec
// section 9: "audit the export itself").
func (db *DB) RecordAuditEvent(ctx context.Context, actorType, actorSubject, action, reason string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: recording audit event %q: begin: %w", action, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := insertAuditEvent(ctx, tx, auditParams{ActorType: actorType, ActorSubject: actorSubject, Action: action, Reason: reason}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: recording audit event %q: commit: %w", action, err)
	}
	return nil
}
