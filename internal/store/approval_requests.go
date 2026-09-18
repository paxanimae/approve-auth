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
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return ApprovalRequest{}, fmt.Errorf("store: creating approval request: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	r, err := scanApprovalRequest(tx.QueryRow(ctx, `
		INSERT INTO approval_requests (application_id, pending_token_hash, verification_code, label, message, return_path, deadline_at, source_ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING `+approvalRequestColumns,
		p.ApplicationID, p.PendingTokenHash, p.VerificationCode, nullableText(p.Label), nullableText(p.Message), nullableText(p.ReturnPath), p.DeadlineAt, nullableInet(p.SourceIP), nullableText(p.UserAgent),
	))
	// A unique-constraint violation (duplicate pending_token_hash or a
	// live verification_code collision) is the caller's to interpret --
	// return it unwrapped-of-transaction-context so pgConstraintName
	// still finds the underlying *pgconn.PgError.
	if err != nil {
		return ApprovalRequest{}, fmt.Errorf("store: creating approval request: %w", err)
	}

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "browser", Action: "request.created",
		ApplicationID: &r.ApplicationID, RequestID: &r.ID,
	}); err != nil {
		return ApprovalRequest{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return ApprovalRequest{}, fmt.Errorf("store: creating approval request: commit: %w", err)
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
	r, err := scanApprovalRequest(db.Pool.QueryRow(ctx, `SELECT `+approvalRequestColumns+` FROM approval_requests WHERE pending_token_hash = $1`, hash))
	if errors.Is(err, pgx.ErrNoRows) {
		return ApprovalRequest{}, false, nil
	}
	if err != nil {
		return ApprovalRequest{}, false, fmt.Errorf("store: looking up approval request: %w", err)
	}
	return r, true, nil
}

// scanner is satisfied by both pgx.Row (QueryRow) and pgx.Rows (each
// Query iteration), so the single-row and list queries below share one
// column list instead of repeating it four times.
type scanner interface {
	Scan(dest ...any) error
}

func scanApprovalRequest(row scanner) (ApprovalRequest, error) {
	var r ApprovalRequest
	err := row.Scan(
		&r.ID, &r.ApplicationID, &r.PendingTokenHash, &r.VerificationCode, &r.Label, &r.Message, &r.ReturnPath,
		&r.Status, &r.RequestedAt, &r.DeadlineAt, &r.DecidedAt, &r.DecidedBy, &r.ClaimDeadlineAt, &r.ClaimedAt,
		&r.PublicDecisionMessage, &r.PrivateNote, &r.UserAgent, &r.Version,
	)
	return r, err
}

const approvalRequestColumns = `id, application_id, pending_token_hash, verification_code, label, message, return_path, status, requested_at, deadline_at, decided_at, decided_by, claim_deadline_at, claimed_at, public_decision_message, private_note, user_agent, version`

// GetApprovalRequestByID is the admin API's lookup, as opposed to
// GetApprovalRequestByTokenHash which is the browser's own.
func (db *DB) GetApprovalRequestByID(ctx context.Context, id uuid.UUID) (ApprovalRequest, bool, error) {
	r, err := scanApprovalRequest(db.Pool.QueryRow(ctx, `SELECT `+approvalRequestColumns+` FROM approval_requests WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ApprovalRequest{}, false, nil
	}
	if err != nil {
		return ApprovalRequest{}, false, fmt.Errorf("store: looking up approval request %s: %w", id, err)
	}
	return r, true, nil
}

// ListApprovalRequests is a first-pass listing for the admin API (spec
// section 9's GET /requests): newest first, optionally filtered by
// application and/or status. Simple limit-bounded, not yet the full
// cursor-paginated/sortable/searchable listing spec section 10
// describes for the console -- that's follow-on work tracked in
// docs/milestone-4-remaining.md.
func (db *DB) ListApprovalRequests(ctx context.Context, applicationID *uuid.UUID, status string, limit int) ([]ApprovalRequest, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT `+approvalRequestColumns+`
		FROM approval_requests
		WHERE ($1::uuid IS NULL OR application_id = $1)
		  AND ($2::text = '' OR status = $2)
		ORDER BY requested_at DESC, id DESC
		LIMIT $3`, applicationID, status, limit)
	if err != nil {
		return nil, fmt.Errorf("store: listing approval requests: %w", err)
	}
	defer rows.Close()

	var out []ApprovalRequest
	for rows.Next() {
		r, err := scanApprovalRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning approval request: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing approval requests: %w", err)
	}
	return out, nil
}

// CancelApprovalRequest cancels a request the browser itself owns, only
// from a cancelable state (pending or approved-but-unclaimed), and
// revokes any unclaimed authorization in the same transaction (spec
// section 5, step 5: "Cancel own pending/unclaimed request and revoke
// any unclaimed grant"). Returns ErrConflict if the request is already
// in a terminal state.
//
// It also consumes the enrollment context sharing this request's
// pending_token_hash, the same cleanup Ack does on the happy path --
// otherwise the browser's still-live pending cookie makes the *next*
// visit to the request page reuse this same enrollment context (spec
// section 5, step 1: "GET may create that context but does not create
// an approval request" -- reuse is deliberate for a retry of the SAME
// in-flight request), and a subsequent submission collides with this
// now-canceled row's still-unique pending_token_hash instead of creating
// a fresh request: the browser silently lands back on this canceled
// request no matter what it just submitted.
func (db *DB) CancelApprovalRequest(ctx context.Context, requestID uuid.UUID) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: cancel: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	var applicationID uuid.UUID
	var pendingTokenHash []byte
	err = tx.QueryRow(ctx, `SELECT status, application_id, pending_token_hash FROM approval_requests WHERE id = $1 FOR UPDATE`, requestID).
		Scan(&status, &applicationID, &pendingTokenHash)
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
	if _, err := tx.Exec(ctx, `UPDATE enrollment_contexts SET consumed_at = now() WHERE pending_token_hash = $1 AND consumed_at IS NULL`, pendingTokenHash); err != nil {
		return fmt.Errorf("store: cancel: consuming enrollment context: %w", err)
	}
	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "browser", Action: "request.canceled",
		ApplicationID: &applicationID, RequestID: &requestID,
	}); err != nil {
		return err
	}

	var revokedAuthorizationID *uuid.UUID
	if err := tx.QueryRow(ctx, `
		UPDATE authorizations SET revoked_at = now(), revocation_reason = 'request canceled', version = version + 1
		WHERE request_id = $1 AND activated_at IS NULL AND revoked_at IS NULL
		RETURNING id`, requestID).Scan(&revokedAuthorizationID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("store: cancel: revoking unclaimed authorization: %w", err)
	}
	if revokedAuthorizationID != nil {
		if err := insertAuditEvent(ctx, tx, auditParams{
			ActorType: "browser", Action: "authorization.revoked",
			ApplicationID: &applicationID, RequestID: &requestID, AuthorizationID: revokedAuthorizationID,
			Reason: "request canceled",
		}); err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: cancel: commit: %w", err)
	}
	return nil
}
