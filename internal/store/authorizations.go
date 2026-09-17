package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ApproveRequest transitions a pending request to approved and creates
// its (unclaimed) authorization in one transaction (spec section 5, step
// 6): approval sets accepted state but the browser must still claim its
// credential -- activated_at stays NULL here. claim_deadline_at is set
// to the earliest of the request's own deadline_at, now+claimTTL, and
// expiresAt (spec section 5: "Approval lasts only until the earlier
// of..."). Returns ErrConflict if the request is not pending or
// expectedVersion is stale.
func (db *DB) ApproveRequest(ctx context.Context, requestID uuid.UUID, expectedVersion int32, expiresAt time.Time, claimTTL time.Duration, label, privateNote, approvedBy string) (Authorization, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return Authorization{}, fmt.Errorf("store: approve: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	var applicationID uuid.UUID
	var version int32
	var requestDeadlineAt time.Time
	err = tx.QueryRow(ctx, `SELECT status, application_id, version, deadline_at FROM approval_requests WHERE id = $1 FOR UPDATE`, requestID).
		Scan(&status, &applicationID, &version, &requestDeadlineAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Authorization{}, ErrConflict
	}
	if err != nil {
		return Authorization{}, fmt.Errorf("store: approve: locking request: %w", err)
	}
	if status != "pending" || version != expectedVersion {
		return Authorization{}, ErrConflict
	}

	claimDeadlineAt := time.Now().Add(claimTTL)
	if requestDeadlineAt.Before(claimDeadlineAt) {
		claimDeadlineAt = requestDeadlineAt
	}
	if expiresAt.Before(claimDeadlineAt) {
		claimDeadlineAt = expiresAt
	}

	if _, err := tx.Exec(ctx, `
		UPDATE approval_requests
		SET status = 'approved', decided_at = now(), decided_by = $2, private_note = $3, claim_deadline_at = $4, version = version + 1
		WHERE id = $1`, requestID, approvedBy, nullableText(privateNote), claimDeadlineAt); err != nil {
		return Authorization{}, fmt.Errorf("store: approve: updating request: %w", err)
	}

	var auth Authorization
	err = tx.QueryRow(ctx, `
		INSERT INTO authorizations (application_id, request_id, label, approved_by, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, application_id, request_id, label, approved_by, approved_at, activated_at, expires_at, revoked_at, revoked_by, revocation_reason, last_seen_at, last_seen_ip, last_seen_user_agent, version`,
		applicationID, requestID, nullableText(label), approvedBy, expiresAt,
	).Scan(
		&auth.ID, &auth.ApplicationID, &auth.RequestID, &auth.Label, &auth.ApprovedBy, &auth.ApprovedAt,
		&auth.ActivatedAt, &auth.ExpiresAt, &auth.RevokedAt, &auth.RevokedBy, &auth.RevocationReason,
		&auth.LastSeenAt, &auth.LastSeenIP, &auth.LastSeenUserAgent, &auth.Version,
	)
	if err != nil {
		return Authorization{}, fmt.Errorf("store: approve: creating authorization: %w", err)
	}

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: approvedBy, Action: "request.approved",
		ApplicationID: &applicationID, RequestID: &requestID, AuthorizationID: &auth.ID,
	}); err != nil {
		return Authorization{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Authorization{}, fmt.Errorf("store: approve: commit: %w", err)
	}
	return auth, nil
}

// DenyRequest transitions a pending request to denied. reason is
// recorded as the private note; publicMessage (optional) is the only
// part ever shown to the browser (spec section 5: "never display
// private admin notes").
func (db *DB) DenyRequest(ctx context.Context, requestID uuid.UUID, expectedVersion int32, reason, publicMessage, deniedBy string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: deny: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	var version int32
	var applicationID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT status, version, application_id FROM approval_requests WHERE id = $1 FOR UPDATE`, requestID).Scan(&status, &version, &applicationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("store: deny: locking request: %w", err)
	}
	if status != "pending" || version != expectedVersion {
		return ErrConflict
	}

	if _, err := tx.Exec(ctx, `
		UPDATE approval_requests
		SET status = 'denied', decided_at = now(), decided_by = $2, private_note = $3, public_decision_message = $4, version = version + 1
		WHERE id = $1`, requestID, deniedBy, nullableText(reason), nullableText(publicMessage)); err != nil {
		return fmt.Errorf("store: deny: updating request: %w", err)
	}

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: deniedBy, Action: "request.denied",
		ApplicationID: &applicationID, RequestID: &requestID, Reason: reason,
	}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: deny: commit: %w", err)
	}
	return nil
}

// RevokeAuthorization invalidates the authorization (and, transitively,
// every credential issued from it -- the authoritative check in
// internal/authz already denies once revoked_at is set, so no separate
// credential-row update is needed). Returns ErrConflict if already
// revoked or expectedVersion is stale.
func (db *DB) RevokeAuthorization(ctx context.Context, authorizationID uuid.UUID, expectedVersion int32, reason, revokedBy string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: revoke: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var applicationID, requestID uuid.UUID
	tag, err := tx.Exec(ctx, `
		UPDATE authorizations
		SET revoked_at = now(), revoked_by = $2, revocation_reason = $3, version = version + 1
		WHERE id = $1 AND revoked_at IS NULL AND version = $4`,
		authorizationID, revokedBy, nullableText(reason), expectedVersion)
	if err != nil {
		return fmt.Errorf("store: revoking authorization %s: %w", authorizationID, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	if err := tx.QueryRow(ctx, `SELECT application_id, request_id FROM authorizations WHERE id = $1`, authorizationID).Scan(&applicationID, &requestID); err != nil {
		return fmt.Errorf("store: revoke: reading application_id: %w", err)
	}

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: revokedBy, Action: "authorization.revoked",
		ApplicationID: &applicationID, RequestID: &requestID, AuthorizationID: &authorizationID, Reason: reason,
	}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: revoke: commit: %w", err)
	}
	return nil
}

// RenewAuthorization extends expires_at, enforcing every rule from spec
// section 7: new_expires_at must exceed both the current expiry and now,
// and must not exceed the credential's hard absolute_expires_at ceiling.
// An unclaimed authorization (no credential yet) cannot be renewed --
// spec section 7: "Renew only active, unrevoked, claimed authorizations."
func (db *DB) RenewAuthorization(ctx context.Context, authorizationID uuid.UUID, expectedVersion int32, newExpiresAt time.Time, renewedBy string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: renew: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var revokedAt *time.Time
	var activatedAt *time.Time
	var currentExpiresAt time.Time
	var version int32
	var credentialAbsoluteExpiresAt *time.Time
	var databaseNow time.Time
	var applicationID, requestID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT z.revoked_at, z.activated_at, z.expires_at, z.version, c.absolute_expires_at, now(), z.application_id, z.request_id
		FROM authorizations z
		LEFT JOIN credentials c ON c.authorization_id = z.id AND c.revoked_at IS NULL
		WHERE z.id = $1
		FOR UPDATE OF z`, authorizationID,
	).Scan(&revokedAt, &activatedAt, &currentExpiresAt, &version, &credentialAbsoluteExpiresAt, &databaseNow, &applicationID, &requestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("store: renew: locking authorization: %w", err)
	}
	if revokedAt != nil || activatedAt == nil || version != expectedVersion {
		return ErrConflict
	}
	if !newExpiresAt.After(currentExpiresAt) || !newExpiresAt.After(databaseNow) {
		return ErrConflict
	}
	if credentialAbsoluteExpiresAt == nil || newExpiresAt.After(*credentialAbsoluteExpiresAt) {
		return ErrConflict
	}

	if _, err := tx.Exec(ctx, `UPDATE authorizations SET expires_at = $2, version = version + 1 WHERE id = $1`, authorizationID, newExpiresAt); err != nil {
		return fmt.Errorf("store: renew: updating authorization: %w", err)
	}

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: renewedBy, Action: "authorization.renewed",
		ApplicationID: &applicationID, RequestID: &requestID, AuthorizationID: &authorizationID,
	}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: renew: commit: %w", err)
	}
	return nil
}

func (db *DB) GetAuthorizationByID(ctx context.Context, id uuid.UUID) (Authorization, bool, error) {
	var auth Authorization
	err := db.Pool.QueryRow(ctx, `
		SELECT id, application_id, request_id, label, approved_by, approved_at, activated_at, expires_at, revoked_at, revoked_by, revocation_reason, last_seen_at, last_seen_ip, last_seen_user_agent, version
		FROM authorizations WHERE id = $1`, id,
	).Scan(
		&auth.ID, &auth.ApplicationID, &auth.RequestID, &auth.Label, &auth.ApprovedBy, &auth.ApprovedAt,
		&auth.ActivatedAt, &auth.ExpiresAt, &auth.RevokedAt, &auth.RevokedBy, &auth.RevocationReason,
		&auth.LastSeenAt, &auth.LastSeenIP, &auth.LastSeenUserAgent, &auth.Version,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Authorization{}, false, nil
	}
	if err != nil {
		return Authorization{}, false, fmt.Errorf("store: looking up authorization %s: %w", id, err)
	}
	return auth, true, nil
}
