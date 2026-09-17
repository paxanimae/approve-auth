package audit

import (
	"context"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresLogger is the only Logger implementation. It issues exactly one
// statement: INSERT INTO audit_events. Nothing in this package can UPDATE
// or DELETE a row -- and even if it tried to, the app_runtime database
// role (migrations/000012_roles_and_grants.up.sql) would reject it.
type PostgresLogger struct {
	pool *pgxpool.Pool
}

func NewPostgresLogger(pool *pgxpool.Pool) *PostgresLogger {
	return &PostgresLogger{pool: pool}
}

func (l *PostgresLogger) Record(ctx context.Context, e Event) error {
	_, err := l.pool.Exec(ctx, `
		INSERT INTO audit_events (
			actor_type, actor_subject, action,
			application_id, request_id, authorization_id,
			correlation_id, source_ip, reason,
			redacted_before, redacted_after, outcome
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		e.ActorType, nullableString(e.ActorSubject), e.Action,
		e.ApplicationID, e.RequestID, e.AuthorizationID,
		e.CorrelationID, nullableIP(e.SourceIP), nullableString(e.Reason),
		nullableBytes(e.RedactedBefore), nullableBytes(e.RedactedAfter), e.Outcome,
	)
	if err != nil {
		return fmt.Errorf("audit: recording %q event: %w", e.Action, err)
	}
	return nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nullableIP(ip net.IP) any {
	if len(ip) == 0 {
		return nil
	}
	return ip
}
