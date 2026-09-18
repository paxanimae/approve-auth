package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ExpireTimedOutRequests transitions pending requests whose deadline has
// passed to 'timed_out' (spec section 7's lifecycle table), writing one
// "request.timed_out" audit event per row, and consumes each request's
// enrollment context (see CancelApprovalRequest's doc comment for why:
// without it, a browser that reloads after its own request timed out
// would reuse the same dead context and collide with this same
// now-timed-out row instead of starting a fresh one). Bounded by limit;
// callers loop until it returns 0 to drain a backlog without one huge
// transaction. This never affects access decisions -- ForwardAuth
// already denies purely from live timestamps regardless of this
// worker's timing (spec section 7: "A worker's delay MUST NOT extend
// permission").
func (db *DB) ExpireTimedOutRequests(ctx context.Context, limit int) (int, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: expiring timed-out requests: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		UPDATE approval_requests SET status = 'timed_out', version = version + 1
		WHERE id IN (
			SELECT id FROM approval_requests
			WHERE status = 'pending' AND deadline_at <= now()
			ORDER BY id
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, application_id, pending_token_hash`, limit)
	if err != nil {
		return 0, fmt.Errorf("store: expiring timed-out requests: %w", err)
	}
	var affected []struct {
		requestID, applicationID uuid.UUID
		pendingTokenHash         []byte
	}
	for rows.Next() {
		var a struct {
			requestID, applicationID uuid.UUID
			pendingTokenHash         []byte
		}
		if err := rows.Scan(&a.requestID, &a.applicationID, &a.pendingTokenHash); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: expiring timed-out requests: scanning: %w", err)
		}
		affected = append(affected, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: expiring timed-out requests: %w", err)
	}

	for _, a := range affected {
		if err := insertAuditEvent(ctx, tx, auditParams{
			ActorType: "system", Action: "request.timed_out",
			ApplicationID: &a.applicationID, RequestID: &a.requestID,
		}); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE enrollment_contexts SET consumed_at = now() WHERE pending_token_hash = $1 AND consumed_at IS NULL`, a.pendingTokenHash); err != nil {
			return 0, fmt.Errorf("store: expiring timed-out requests: consuming enrollment context: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("store: expiring timed-out requests: commit: %w", err)
	}
	return len(affected), nil
}

// ExpireClaimWindows transitions approved-but-unclaimed requests whose
// claim window has passed to 'claim_expired', revokes their still-
// unclaimed authorization, and consumes their enrollment context (see
// CancelApprovalRequest's doc comment for why) -- the time-driven
// equivalent of CancelApprovalRequest's existing "revoke any unclaimed
// grant" step, just triggered by the claim deadline passing instead of
// an explicit cancel. Writes "request.claim_expired" and
// "authorization.revoked" audit events.
func (db *DB) ExpireClaimWindows(ctx context.Context, limit int) (int, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: expiring claim windows: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		UPDATE approval_requests SET status = 'claim_expired', version = version + 1
		WHERE id IN (
			SELECT id FROM approval_requests
			WHERE status = 'approved' AND claim_deadline_at <= now()
			ORDER BY id
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, application_id, pending_token_hash`, limit)
	if err != nil {
		return 0, fmt.Errorf("store: expiring claim windows: %w", err)
	}
	var affected []struct {
		requestID, applicationID uuid.UUID
		pendingTokenHash         []byte
	}
	for rows.Next() {
		var a struct {
			requestID, applicationID uuid.UUID
			pendingTokenHash         []byte
		}
		if err := rows.Scan(&a.requestID, &a.applicationID, &a.pendingTokenHash); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: expiring claim windows: scanning: %w", err)
		}
		affected = append(affected, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: expiring claim windows: %w", err)
	}

	for _, a := range affected {
		if err := insertAuditEvent(ctx, tx, auditParams{
			ActorType: "system", Action: "request.claim_expired",
			ApplicationID: &a.applicationID, RequestID: &a.requestID,
		}); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE enrollment_contexts SET consumed_at = now() WHERE pending_token_hash = $1 AND consumed_at IS NULL`, a.pendingTokenHash); err != nil {
			return 0, fmt.Errorf("store: expiring claim windows: consuming enrollment context: %w", err)
		}

		var authorizationID uuid.UUID
		err := tx.QueryRow(ctx, `
			UPDATE authorizations SET revoked_at = now(), revocation_reason = 'claim window expired', version = version + 1
			WHERE request_id = $1 AND activated_at IS NULL AND revoked_at IS NULL
			RETURNING id`, a.requestID).Scan(&authorizationID)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // approved requests always get an authorization, but be defensive
		}
		if err != nil {
			return 0, fmt.Errorf("store: expiring claim windows: revoking authorization: %w", err)
		}
		if err := insertAuditEvent(ctx, tx, auditParams{
			ActorType: "system", Action: "authorization.revoked",
			ApplicationID: &a.applicationID, RequestID: &a.requestID, AuthorizationID: &authorizationID,
			Reason: "claim window expired",
		}); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("store: expiring claim windows: commit: %w", err)
	}
	return len(affected), nil
}

// RecordExpiredAuthorizations writes one idempotent "authorization.expired"
// audit event per authorization whose expiry has passed (spec section
// 12: "Expiry worker writes one idempotent expiry event per
// authorization without governing effective expiry"). It never mutates
// the authorization itself -- internal/authz already denies access from
// the live expires_at comparison regardless of whether or when this
// runs. Idempotency comes from NOT EXISTS rather than a status flag, so
// a crash mid-batch just means the next run picks up where it left off.
func (db *DB) RecordExpiredAuthorizations(ctx context.Context, limit int) (int, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: recording expired authorizations: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT a.id, a.application_id, a.request_id
		FROM authorizations a
		WHERE a.activated_at IS NOT NULL AND a.revoked_at IS NULL AND a.expires_at <= now()
		  AND NOT EXISTS (
			SELECT 1 FROM audit_events e
			WHERE e.authorization_id = a.id AND e.action = 'authorization.expired'
		  )
		ORDER BY a.id
		LIMIT $1
		FOR UPDATE OF a SKIP LOCKED`, limit)
	if err != nil {
		return 0, fmt.Errorf("store: recording expired authorizations: %w", err)
	}
	var affected []struct{ authID, appID, reqID uuid.UUID }
	for rows.Next() {
		var a struct{ authID, appID, reqID uuid.UUID }
		if err := rows.Scan(&a.authID, &a.appID, &a.reqID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: recording expired authorizations: scanning: %w", err)
		}
		affected = append(affected, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: recording expired authorizations: %w", err)
	}

	for _, a := range affected {
		if err := insertAuditEvent(ctx, tx, auditParams{
			ActorType: "system", Action: "authorization.expired",
			ApplicationID: &a.appID, RequestID: &a.reqID, AuthorizationID: &a.authID,
		}); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("store: recording expired authorizations: commit: %w", err)
	}
	return len(affected), nil
}

// PurgeExpiredClaimEnvelopes deletes expired claim-retry envelopes and
// consumes the pending proof they were guarding -- the same two steps
// Ack performs on an explicit acknowledgment (spec section 5: "If no
// acknowledgment arrives, purge the envelope at ten minutes and consume
// pending proof").
func (db *DB) PurgeExpiredClaimEnvelopes(ctx context.Context, limit int) (int, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT c.request_id, r.pending_token_hash
		FROM claim_results c
		JOIN approval_requests r ON r.id = c.request_id
		WHERE c.expires_at <= now()
		ORDER BY c.request_id
		LIMIT $1`, limit)
	if err != nil {
		return 0, fmt.Errorf("store: purging expired claim envelopes: %w", err)
	}
	var candidates []struct {
		requestID uuid.UUID
		tokenHash []byte
	}
	for rows.Next() {
		var c struct {
			requestID uuid.UUID
			tokenHash []byte
		}
		if err := rows.Scan(&c.requestID, &c.tokenHash); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: purging expired claim envelopes: scanning: %w", err)
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: purging expired claim envelopes: %w", err)
	}

	purged := 0
	for _, c := range candidates {
		if _, err := db.Pool.Exec(ctx, `DELETE FROM claim_results WHERE request_id = $1 AND expires_at <= now()`, c.requestID); err != nil {
			return purged, fmt.Errorf("store: purging expired claim envelopes: deleting envelope: %w", err)
		}
		if _, err := db.Pool.Exec(ctx, `
			UPDATE enrollment_contexts SET consumed_at = now()
			WHERE pending_token_hash = $1 AND consumed_at IS NULL`, c.tokenHash); err != nil {
			return purged, fmt.Errorf("store: purging expired claim envelopes: consuming pending proof: %w", err)
		}
		purged++
	}
	return purged, nil
}

// PurgeExpiredRateLimitBuckets deletes rate_limit_buckets rows past
// their own expires_at.
func (db *DB) PurgeExpiredRateLimitBuckets(ctx context.Context, limit int) (int, error) {
	tag, err := db.Pool.Exec(ctx, `
		DELETE FROM rate_limit_buckets WHERE (bucket_key, window_start) IN (
			SELECT bucket_key, window_start FROM rate_limit_buckets
			WHERE expires_at <= now()
			ORDER BY window_start
			LIMIT $1
		)`, limit)
	if err != nil {
		return 0, fmt.Errorf("store: purging expired rate limit buckets: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// PurgeExpiredIdempotencyRecords deletes idempotency_records rows past
// their own expires_at (spec section 12: "idempotency records 24 hours").
func (db *DB) PurgeExpiredIdempotencyRecords(ctx context.Context, limit int) (int, error) {
	tag, err := db.Pool.Exec(ctx, `
		DELETE FROM idempotency_records WHERE id IN (
			SELECT id FROM idempotency_records
			WHERE expires_at <= now()
			ORDER BY id
			LIMIT $1
		)`, limit)
	if err != nil {
		return 0, fmt.Errorf("store: purging expired idempotency records: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// RedactOldClientMetadata blanks approval_requests.source_ip/user_agent
// and authorizations.last_seen_ip/last_seen_user_agent once they're
// older than maxAge (spec section 12: "IP/user-agent fields 30 days").
// The rows themselves persist until their own, separate 90-day
// retention window -- this only nulls the fields.
func (db *DB) RedactOldClientMetadata(ctx context.Context, maxAge time.Duration, limit int) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	tag1, err := db.Pool.Exec(ctx, `
		UPDATE approval_requests SET source_ip = NULL, user_agent = NULL
		WHERE id IN (
			SELECT id FROM approval_requests
			WHERE requested_at <= $1 AND (source_ip IS NOT NULL OR user_agent IS NOT NULL)
			ORDER BY id
			LIMIT $2
		)`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("store: redacting old request metadata: %w", err)
	}
	tag2, err := db.Pool.Exec(ctx, `
		UPDATE authorizations SET last_seen_ip = NULL, last_seen_user_agent = NULL
		WHERE id IN (
			SELECT id FROM authorizations
			WHERE last_seen_at <= $1 AND (last_seen_ip IS NOT NULL OR last_seen_user_agent IS NOT NULL)
			ORDER BY id
			LIMIT $2
		)`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("store: redacting old authorization metadata: %w", err)
	}
	return int(tag1.RowsAffected() + tag2.RowsAffected()), nil
}

// RedactOldReturnPaths blanks approval_requests.return_path once it's
// older than maxAge (spec section 5: "purge them after seven days").
func (db *DB) RedactOldReturnPaths(ctx context.Context, maxAge time.Duration, limit int) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	tag, err := db.Pool.Exec(ctx, `
		UPDATE approval_requests SET return_path = NULL
		WHERE id IN (
			SELECT id FROM approval_requests
			WHERE requested_at <= $1 AND return_path IS NOT NULL
			ORDER BY id
			LIMIT $2
		)`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("store: redacting old return paths: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// PurgeResolvedRecords deletes one terminated request, and its
// authorization/credentials if it has them, once maxAge has passed
// since termination (spec section 12: "resolved requests and inactive
// authorizations ... 90 days after termination"). A request is only a
// candidate if it has no authorization at all, or its authorization is
// itself already terminal (revoked, or expired and never renewed) --
// this is deliberately conservative: a 'claimed' request whose
// authorization is still live is never touched, no matter how old
// requested_at is, since deleting it would remove the row ForwardAuth's
// authoritative check still depends on.
//
// Deletes bottom-up through the schema's foreign keys (credentials ->
// authorization -> request) since none of them cascade; audit_events'
// application_id/request_id/authorization_id columns are ON DELETE SET
// NULL, so the audit trail survives independently for its own longer
// (365-day) retention window.
func (db *DB) PurgeResolvedRecords(ctx context.Context, maxAge time.Duration, limit int) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	rows, err := db.Pool.Query(ctx, `
		WITH candidates AS (
			SELECT r.id AS request_id, a.id AS authorization_id,
			       coalesce(a.revoked_at, CASE WHEN a.expires_at <= now() THEN a.expires_at END, r.decided_at, r.requested_at) AS terminated_at
			FROM approval_requests r
			LEFT JOIN authorizations a ON a.request_id = r.id
			WHERE r.status IN ('denied', 'canceled', 'timed_out', 'claim_expired', 'claimed')
			  AND (a.id IS NULL OR a.revoked_at IS NOT NULL OR (a.activated_at IS NOT NULL AND a.expires_at <= now()))
		)
		SELECT request_id, authorization_id FROM candidates
		WHERE terminated_at <= $1
		ORDER BY request_id
		LIMIT $2`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("store: purging resolved records: finding candidates: %w", err)
	}
	var candidates []struct {
		requestID uuid.UUID
		authID    *uuid.UUID
	}
	for rows.Next() {
		var c struct {
			requestID uuid.UUID
			authID    *uuid.UUID
		}
		if err := rows.Scan(&c.requestID, &c.authID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: purging resolved records: scanning: %w", err)
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: purging resolved records: %w", err)
	}

	purged := 0
	for _, c := range candidates {
		if err := db.purgeOneResolvedRecord(ctx, c.requestID, c.authID); err != nil {
			return purged, err
		}
		purged++
	}
	return purged, nil
}

func (db *DB) purgeOneResolvedRecord(ctx context.Context, requestID uuid.UUID, authID *uuid.UUID) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: purging resolved record %s: begin: %w", requestID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if authID != nil {
		if _, err := tx.Exec(ctx, `DELETE FROM credentials WHERE authorization_id = $1`, *authID); err != nil {
			return fmt.Errorf("store: purging resolved record %s: deleting credentials: %w", requestID, err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM authorizations WHERE id = $1`, *authID); err != nil {
			return fmt.Errorf("store: purging resolved record %s: deleting authorization: %w", requestID, err)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM claim_results WHERE request_id = $1`, requestID); err != nil {
		return fmt.Errorf("store: purging resolved record %s: deleting claim envelope: %w", requestID, err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, requestID); err != nil {
		return fmt.Errorf("store: purging resolved record %s: deleting request: %w", requestID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: purging resolved record %s: commit: %w", requestID, err)
	}
	return nil
}

// PurgeOldAuditEvents deletes audit_events rows older than maxAge (spec
// section 12: "audit 365 days"). Runs under the app_maintenance role in
// production (spec section 11, control 10: the runtime role can insert
// but not delete audit records).
func (db *DB) PurgeOldAuditEvents(ctx context.Context, maxAge time.Duration, limit int) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	tag, err := db.Pool.Exec(ctx, `
		DELETE FROM audit_events WHERE id IN (
			SELECT id FROM audit_events
			WHERE occurred_at <= $1
			ORDER BY id
			LIMIT $2
		)`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("store: purging old audit events: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
