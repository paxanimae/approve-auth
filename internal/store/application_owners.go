package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// GrantApplicationOwner records that subject owns applicationID (spec:
// "An ApplicationOwner can accept and revoke requests to his
// application ... but cannot control anything else") -- idempotent, so
// granting an already-owned application is a no-op, not an error.
func (db *DB) GrantApplicationOwner(ctx context.Context, applicationID uuid.UUID, subject, grantedBy string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: granting application owner: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO application_owners (application_id, subject) VALUES ($1, $2)
		ON CONFLICT (application_id, subject) DO NOTHING`, applicationID, subject); err != nil {
		return fmt.Errorf("store: granting application owner: %w", err)
	}
	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: grantedBy, Action: "application.owner_granted",
		ApplicationID: &applicationID, Reason: subject,
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: granting application owner: commit: %w", err)
	}
	return nil
}

// RevokeApplicationOwner is GrantApplicationOwner's inverse -- also
// idempotent, revoking a non-owner is a no-op.
func (db *DB) RevokeApplicationOwner(ctx context.Context, applicationID uuid.UUID, subject, revokedBy string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: revoking application owner: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM application_owners WHERE application_id = $1 AND subject = $2`, applicationID, subject); err != nil {
		return fmt.Errorf("store: revoking application owner: %w", err)
	}
	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: revokedBy, Action: "application.owner_revoked",
		ApplicationID: &applicationID, Reason: subject,
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: revoking application owner: commit: %w", err)
	}
	return nil
}

// ListApplicationOwners is the admin API's view of who owns a given
// application, oldest grant first.
func (db *DB) ListApplicationOwners(ctx context.Context, applicationID uuid.UUID) ([]string, error) {
	rows, err := db.Pool.Query(ctx, `SELECT subject FROM application_owners WHERE application_id = $1 ORDER BY created_at ASC`, applicationID)
	if err != nil {
		return nil, fmt.Errorf("store: listing application owners: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var subject string
		if err := rows.Scan(&subject); err != nil {
			return nil, fmt.Errorf("store: scanning application owner: %w", err)
		}
		out = append(out, subject)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing application owners: %w", err)
	}
	return out, nil
}

// GetOwnedApplicationIDs is the other direction from ListApplicationOwners:
// every application a given subject owns, resolved fresh (never cached
// on the admin session) so a revoked grant takes effect on this
// subject's very next request, not just their next login -- see
// migration 000016's own comment on why role itself doesn't need the
// same freshness but this does.
func (db *DB) GetOwnedApplicationIDs(ctx context.Context, subject string) ([]uuid.UUID, error) {
	rows, err := db.Pool.Query(ctx, `SELECT application_id FROM application_owners WHERE subject = $1`, subject)
	if err != nil {
		return nil, fmt.Errorf("store: listing owned applications: %w", err)
	}
	defer rows.Close()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: scanning owned application: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing owned applications: %w", err)
	}
	return out, nil
}
