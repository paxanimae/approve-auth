package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/frid-iks/traefik-manual-proxy/internal/metrics"
)

// auditParams is the subset of audit_events columns every mutation in
// this package fills in directly. Kept unexported and separate from
// internal/audit.Event: spec section 12 requires "mutations fail if
// their audit event cannot commit," which means the INSERT has to run
// inside the same transaction as the mutation itself, not through a
// separately-pooled logger the way internal/authz's (non-mutating,
// deliberately unaudited-per-request) allow/deny checks would use.
type auditParams struct {
	ActorType       string
	ActorSubject    string
	Action          string
	ApplicationID   *uuid.UUID
	RequestID       *uuid.UUID
	AuthorizationID *uuid.UUID
	Reason          string
	Outcome         string
}

func insertAuditEvent(ctx context.Context, tx pgx.Tx, p auditParams) error {
	outcome := p.Outcome
	if outcome == "" {
		outcome = "success"
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO audit_events (actor_type, actor_subject, action, application_id, request_id, authorization_id, correlation_id, reason, outcome)
		VALUES ($1, $2, $3, $4, $5, $6, gen_random_uuid(), $7, $8)`,
		p.ActorType, nullableText(p.ActorSubject), p.Action, p.ApplicationID, p.RequestID, p.AuthorizationID, nullableText(p.Reason), outcome,
	)
	if err != nil {
		metrics.AuditInsertFailures.Inc()
		return fmt.Errorf("store: recording audit event %q: %w", p.Action, err)
	}
	return nil
}
