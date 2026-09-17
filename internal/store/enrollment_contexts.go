package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateEnrollmentContext bootstraps a pending browser's CSRF secret
// before any request exists (spec section 5, step 2). The caller
// generates pendingTokenHash/csrfSecret and owns the raw cookie value;
// this just persists them.
func (db *DB) CreateEnrollmentContext(ctx context.Context, applicationID uuid.UUID, pendingTokenHash, csrfSecret []byte, expiresAt time.Time) (EnrollmentContext, error) {
	var ec EnrollmentContext
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO enrollment_contexts (application_id, pending_token_hash, csrf_secret, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, application_id, pending_token_hash, csrf_secret, created_at, expires_at, consumed_at`,
		applicationID, pendingTokenHash, csrfSecret, expiresAt,
	).Scan(&ec.ID, &ec.ApplicationID, &ec.PendingTokenHash, &ec.CSRFSecret, &ec.CreatedAt, &ec.ExpiresAt, &ec.ConsumedAt)
	if err != nil {
		return EnrollmentContext{}, fmt.Errorf("store: creating enrollment context: %w", err)
	}
	return ec, nil
}

// GetLiveEnrollmentContextByTokenHash returns (ctx, true, nil) only if a
// context exists for hash, is unexpired, and is unconsumed. Any other
// case (not found, expired, consumed) returns (_, false, nil) uniformly
// -- callers should treat all three as "bootstrap a new one," not branch
// on which.
func (db *DB) GetLiveEnrollmentContextByTokenHash(ctx context.Context, hash []byte) (EnrollmentContext, bool, error) {
	var ec EnrollmentContext
	err := db.Pool.QueryRow(ctx, `
		SELECT id, application_id, pending_token_hash, csrf_secret, created_at, expires_at, consumed_at
		FROM enrollment_contexts
		WHERE pending_token_hash = $1 AND consumed_at IS NULL AND expires_at > now()`, hash,
	).Scan(&ec.ID, &ec.ApplicationID, &ec.PendingTokenHash, &ec.CSRFSecret, &ec.CreatedAt, &ec.ExpiresAt, &ec.ConsumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return EnrollmentContext{}, false, nil
	}
	if err != nil {
		return EnrollmentContext{}, false, fmt.Errorf("store: looking up enrollment context: %w", err)
	}
	return ec, true, nil
}

// ConsumeEnrollmentContext marks a context consumed (spec section 5:
// pending proof is consumed on ack, or purged after 10 minutes if no ack
// arrives -- see claims.go). Consuming twice is a harmless no-op.
func (db *DB) ConsumeEnrollmentContext(ctx context.Context, id uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `UPDATE enrollment_contexts SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("store: consuming enrollment context %s: %w", id, err)
	}
	return nil
}
