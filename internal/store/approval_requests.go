package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrConflict means a caller's expected state (status/version) didn't
// match the current row -- an optimistic-concurrency loss, a stale
// If-Match, or a request already handled by someone else. Callers map
// this to 409, per spec section 9.
var ErrConflict = errors.New("store: conflict (stale version or unexpected state)")

// CreateApprovalRequest stores one pending request (spec section 5, step
// 3). pendingTokenHash is the same hash as the enrollment context that
// bootstrapped it -- both tables share it so every subsequent lookup
// (status, cancel, claim) uses one hash regardless of lifecycle stage.
func (db *DB) CreateApprovalRequest(ctx context.Context, p CreateApprovalRequestParams) (ApprovalRequest, error) {
	var r ApprovalRequest
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO approval_requests (application_id, pending_token_hash, verification_code, label, message, return_path, deadline_at, source_ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, application_id, pending_token_hash, verification_code, label, message, return_path, status, requested_at, deadline_at, decided_at, decided_by, claim_deadline_at, claimed_at, public_decision_message, private_note, user_agent, version`,
		p.ApplicationID, p.PendingTokenHash, p.VerificationCode, nullableText(p.Label), nullableText(p.Message), nullableText(p.ReturnPath), p.DeadlineAt, nullableInet(p.SourceIP), nullableText(p.UserAgent),
	).Scan(
		&r.ID, &r.ApplicationID, &r.PendingTokenHash, &r.VerificationCode, &r.Label, &r.Message, &r.ReturnPath,
		&r.Status, &r.RequestedAt, &r.DeadlineAt, &r.DecidedAt, &r.DecidedBy, &r.ClaimDeadlineAt, &r.ClaimedAt,
		&r.PublicDecisionMessage, &r.PrivateNote, &r.UserAgent, &r.Version,
	)
	if err != nil {
		return ApprovalRequest{}, fmt.Errorf("store: creating approval request: %w", err)
	}
	return r, nil
}

// CreateApprovalRequestParams avoids a long positional-argument list for
// CreateApprovalRequest; VerificationCode and DeadlineAt are the only
// required fields beyond the two identifying the browser.
type CreateApprovalRequestParams struct {
	ApplicationID    uuid.UUID
	PendingTokenHash []byte
	VerificationCode string
	Label            string
	Message          string
	ReturnPath       string
	DeadlineAt       time.Time
	SourceIP         string
	UserAgent        string
}

// GetApprovalRequestByTokenHash is how the browser's own pending proof
// resolves to its request -- status/cancel/claim all start here. Callers
// distinguish "not found" via the bool, not an error.
func (db *DB) GetApprovalRequestByTokenHash(ctx context.Context, hash []byte) (ApprovalRequest, bool, error) {
	var r ApprovalRequest
	err := db.Pool.QueryRow(ctx, `
		SELECT id, application_id, pending_token_hash, verification_code, label, message, return_path, status, requested_at, deadline_at, decided_at, decided_by, claim_deadline_at, claimed_at, public_decision_message, private_note, user_agent, version
		FROM approval_requests
		WHERE pending_token_hash = $1`, hash,
	).Scan(
		&r.ID, &r.ApplicationID, &r.PendingTokenHash, &r.VerificationCode, &r.Label, &r.Message, &r.ReturnPath,
		&r.Status, &r.RequestedAt, &r.DeadlineAt, &r.DecidedAt, &r.DecidedBy, &r.ClaimDeadlineAt, &r.ClaimedAt,
		&r.PublicDecisionMessage, &r.PrivateNote, &r.UserAgent, &r.Version,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ApprovalRequest{}, false, nil
	}
	if err != nil {
		return ApprovalRequest{}, false, fmt.Errorf("store: looking up approval request: %w", err)
	}
	return r, true, nil
}

// CancelApprovalRequest cancels a request the browser itself owns, only
// from a cancelable state (pending or approved-but-unclaimed), and
// revokes any unclaimed authorization in the same transaction (spec
// section 5, step 5: "Cancel own pending/unclaimed request and revoke
// any unclaimed grant"). Returns ErrConflict if the request is already
// in a terminal state.
func (db *DB) CancelApprovalRequest(ctx context.Context, requestID uuid.UUID) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: cancel: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id = $1 FOR UPDATE`, requestID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("store: cancel: locking request: %w", err)
	}
	if status != "pending" && status != "approved" {
		return ErrConflict
	}

	if _, err := tx.Exec(ctx, `UPDATE approval_requests SET status = 'canceled', version = version + 1 WHERE id = $1`, requestID); err != nil {
		return fmt.Errorf("store: cancel: updating request: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE authorizations SET revoked_at = now(), revocation_reason = 'request canceled', version = version + 1
		WHERE request_id = $1 AND activated_at IS NULL AND revoked_at IS NULL`, requestID); err != nil {
		return fmt.Errorf("store: cancel: revoking unclaimed authorization: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: cancel: commit: %w", err)
	}
	return nil
}
