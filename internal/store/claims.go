package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrRequestNotClaimable covers every non-retry reason a claim can't
// proceed: the request was never approved, was denied/canceled/timed
// out, or its claim window has passed (spec section 5: "Approval lasts
// only until the earlier of the request's 24-hour deadline, 30 minutes
// after approval, or the chosen authorization end time").
var ErrRequestNotClaimable = errors.New("store: request is not in a claimable state")

// ErrAlreadyClaimedNoEnvelope means the request is already claimed but
// its retry envelope is gone (consumed by ack, or purged after its
// 10-minute TTL) -- the browser must request access again; the raw
// token is never recoverable at this point (spec section 5).
var ErrAlreadyClaimedNoEnvelope = errors.New("store: already claimed and the retry envelope is no longer available")

// ClaimApproved is the retry-safe core of spec section 5 step 7. On a
// fresh claim it locks the request, verifies it's approved and within
// its claim window, creates the credential, activates the authorization,
// and marks the request claimed -- all in one transaction. On a repeat
// call with the same pending proof (status already 'claimed'), it does
// nothing and reports alreadyClaimed=true so the caller retrieves the
// existing envelope instead of minting a second credential.
func (db *DB) ClaimApproved(ctx context.Context, requestID uuid.UUID, tokenHash []byte, credentialMaxAge time.Duration) (credentialID, applicationID uuid.UUID, alreadyClaimed bool, err error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, false, fmt.Errorf("store: claim: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	var claimDeadlineAt *time.Time
	var authorizationID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT r.status, r.claim_deadline_at, r.application_id, z.id
		FROM approval_requests r
		JOIN authorizations z ON z.request_id = r.id
		WHERE r.id = $1
		FOR UPDATE OF r`, requestID,
	).Scan(&status, &claimDeadlineAt, &applicationID, &authorizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.UUID{}, uuid.UUID{}, false, ErrRequestNotClaimable
	}
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, false, fmt.Errorf("store: claim: locking request: %w", err)
	}

	if status == "claimed" {
		return uuid.UUID{}, applicationID, true, nil
	}
	if status != "approved" || claimDeadlineAt == nil || !time.Now().Before(*claimDeadlineAt) {
		return uuid.UUID{}, uuid.UUID{}, false, ErrRequestNotClaimable
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO credentials (authorization_id, application_id, token_hash, absolute_expires_at)
		VALUES ($1, $2, $3, now() + $4)
		RETURNING id`, authorizationID, applicationID, tokenHash, credentialMaxAge,
	).Scan(&credentialID)
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, false, fmt.Errorf("store: claim: creating credential: %w", err)
	}

	if _, err := tx.Exec(ctx, `UPDATE authorizations SET activated_at = now(), version = version + 1 WHERE id = $1`, authorizationID); err != nil {
		return uuid.UUID{}, uuid.UUID{}, false, fmt.Errorf("store: claim: activating authorization: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE approval_requests SET status = 'claimed', claimed_at = now(), version = version + 1 WHERE id = $1`, requestID); err != nil {
		return uuid.UUID{}, uuid.UUID{}, false, fmt.Errorf("store: claim: updating request: %w", err)
	}

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "browser", Action: "claim.completed",
		ApplicationID: &applicationID, RequestID: &requestID, AuthorizationID: &authorizationID,
	}); err != nil {
		return uuid.UUID{}, uuid.UUID{}, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.UUID{}, uuid.UUID{}, false, fmt.Errorf("store: claim: commit: %w", err)
	}
	return credentialID, applicationID, false, nil
}

// SaveClaimEnvelope persists the encrypted claim-retry envelope (spec
// section 5): the caller has already encrypted the raw token with the
// configured AES key -- store just holds the opaque bytes, the same
// separation as internal/audit not knowing about the DB role that
// enforces its immutability.
func (db *DB) SaveClaimEnvelope(ctx context.Context, requestID, credentialID uuid.UUID, encryptionKeyID string, nonce, ciphertext []byte, expiresAt time.Time) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO claim_results (request_id, credential_id, encryption_key_id, nonce, ciphertext, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (request_id) DO UPDATE SET
			credential_id = EXCLUDED.credential_id,
			encryption_key_id = EXCLUDED.encryption_key_id,
			nonce = EXCLUDED.nonce,
			ciphertext = EXCLUDED.ciphertext,
			expires_at = EXCLUDED.expires_at`,
		requestID, credentialID, encryptionKeyID, nonce, ciphertext, expiresAt)
	if err != nil {
		return fmt.Errorf("store: saving claim envelope for request %s: %w", requestID, err)
	}
	return nil
}

// GetLiveClaimEnvelope returns (_, false, nil) if no unexpired envelope
// exists for requestID -- expired-but-not-yet-purged rows are treated
// identically to purged ones.
func (db *DB) GetLiveClaimEnvelope(ctx context.Context, requestID uuid.UUID) (ClaimResult, bool, error) {
	var cr ClaimResult
	err := db.Pool.QueryRow(ctx, `
		SELECT request_id, credential_id, encryption_key_id, nonce, ciphertext, expires_at
		FROM claim_results WHERE request_id = $1 AND expires_at > now()`, requestID,
	).Scan(&cr.RequestID, &cr.CredentialID, &cr.EncryptionKeyID, &cr.Nonce, &cr.Ciphertext, &cr.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimResult{}, false, nil
	}
	if err != nil {
		return ClaimResult{}, false, fmt.Errorf("store: looking up claim envelope for request %s: %w", requestID, err)
	}
	return cr, true, nil
}

// DeleteClaimEnvelope consumes the envelope (spec section 5: ack
// consumes it; so does the 10-minute purge a later milestone's worker
// implements). Deleting twice is a harmless no-op.
func (db *DB) DeleteClaimEnvelope(ctx context.Context, requestID uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM claim_results WHERE request_id = $1`, requestID)
	if err != nil {
		return fmt.Errorf("store: deleting claim envelope for request %s: %w", requestID, err)
	}
	return nil
}
