package store_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestExpireTimedOutRequests(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "postgres", "devpassword")

	appID := insertApplication(t, ctx, conn, "retention-timeout.example.test")
	overdueID := insertApprovalRequest(t, ctx, conn, appID, "TOUT-0001")
	overdueEC := insertMatchingEnrollmentContext(t, ctx, conn, appID, "TOUT-0001")
	if _, err := conn.Exec(ctx, `UPDATE approval_requests SET deadline_at = now() - interval '1 hour' WHERE id = $1`, overdueID); err != nil {
		t.Fatalf("backdating deadline: %v", err)
	}
	stillPendingID := insertApprovalRequest(t, ctx, conn, appID, "TOUT-0002")

	n, err := db.ExpireTimedOutRequests(ctx, 100)
	if err != nil {
		t.Fatalf("ExpireTimedOutRequests: %v", err)
	}
	if n != 1 {
		t.Errorf("ExpireTimedOutRequests returned %d, want 1", n)
	}

	var status string
	if err := conn.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id = $1`, overdueID).Scan(&status); err != nil {
		t.Fatalf("checking overdue request: %v", err)
	}
	if status != "timed_out" {
		t.Errorf("overdue request status = %q, want timed_out", status)
	}
	if err := conn.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id = $1`, stillPendingID).Scan(&status); err != nil {
		t.Fatalf("checking still-pending request: %v", err)
	}
	if status != "pending" {
		t.Errorf("still-pending request status = %q, want pending (untouched)", status)
	}

	var auditCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE request_id = $1 AND action = 'request.timed_out'`, overdueID).Scan(&auditCount); err != nil {
		t.Fatalf("checking audit event: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("audit event count = %d, want 1", auditCount)
	}

	// Regression: see CancelApprovalRequest's doc comment -- a timed-out
	// request's enrollment context must also be consumed, or a browser
	// that reloads keeps reusing the same dead context.
	var consumedAt *time.Time
	if err := conn.QueryRow(ctx, `SELECT consumed_at FROM enrollment_contexts WHERE id = $1`, overdueEC).Scan(&consumedAt); err != nil {
		t.Fatalf("checking enrollment context: %v", err)
	}
	if consumedAt == nil {
		t.Error("expected the timed-out request's enrollment context to be consumed")
	}
}

func TestExpireClaimWindows(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "postgres", "devpassword")

	appID := insertApplication(t, ctx, conn, "retention-claimwindow.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, "CLMW-0001")
	reqEC := insertMatchingEnrollmentContext(t, ctx, conn, appID, "CLMW-0001")
	if _, err := conn.Exec(ctx, `UPDATE approval_requests SET status = 'approved', claim_deadline_at = now() - interval '1 minute' WHERE id = $1`, reqID); err != nil {
		t.Fatalf("marking request approved-and-overdue: %v", err)
	}
	authID := insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{ExpiresAt: time.Now().Add(30 * 24 * time.Hour)})

	n, err := db.ExpireClaimWindows(ctx, 100)
	if err != nil {
		t.Fatalf("ExpireClaimWindows: %v", err)
	}
	if n != 1 {
		t.Errorf("ExpireClaimWindows returned %d, want 1", n)
	}

	var status string
	if err := conn.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id = $1`, reqID).Scan(&status); err != nil {
		t.Fatalf("checking request status: %v", err)
	}
	if status != "claim_expired" {
		t.Errorf("request status = %q, want claim_expired", status)
	}

	var revokedAt *time.Time
	var reason *string
	if err := conn.QueryRow(ctx, `SELECT revoked_at, revocation_reason FROM authorizations WHERE id = $1`, authID).Scan(&revokedAt, &reason); err != nil {
		t.Fatalf("checking authorization: %v", err)
	}
	if revokedAt == nil {
		t.Error("authorization should be revoked")
	}
	if reason == nil || *reason != "claim window expired" {
		t.Errorf("revocation_reason = %v, want \"claim window expired\"", reason)
	}

	for _, action := range []string{"request.claim_expired", "authorization.revoked"} {
		var count int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE request_id = $1 AND action = $2`, reqID, action).Scan(&count); err != nil {
			t.Fatalf("checking audit event %s: %v", action, err)
		}
		if count != 1 {
			t.Errorf("audit event %s count = %d, want 1", action, count)
		}
	}

	// Regression: see CancelApprovalRequest's doc comment -- a
	// claim_expired request's enrollment context must also be consumed.
	var consumedAt *time.Time
	if err := conn.QueryRow(ctx, `SELECT consumed_at FROM enrollment_contexts WHERE id = $1`, reqEC).Scan(&consumedAt); err != nil {
		t.Fatalf("checking enrollment context: %v", err)
	}
	if consumedAt == nil {
		t.Error("expected the claim_expired request's enrollment context to be consumed")
	}
}

func TestRecordExpiredAuthorizations_IsIdempotent(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "postgres", "devpassword")

	appID := insertApplication(t, ctx, conn, "retention-authexpiry.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, "AEXP-0001")
	activatedAt := time.Now().Add(-48 * time.Hour)
	authID := insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{
		ActivatedAt: &activatedAt, ExpiresAt: time.Now().Add(-time.Hour),
	})

	n, err := db.RecordExpiredAuthorizations(ctx, 100)
	if err != nil {
		t.Fatalf("RecordExpiredAuthorizations (first): %v", err)
	}
	if n != 1 {
		t.Errorf("first call returned %d, want 1", n)
	}

	n, err = db.RecordExpiredAuthorizations(ctx, 100)
	if err != nil {
		t.Fatalf("RecordExpiredAuthorizations (second): %v", err)
	}
	if n != 0 {
		t.Errorf("second call returned %d, want 0 (already recorded)", n)
	}

	var count int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE authorization_id = $1 AND action = 'authorization.expired'`, authID).Scan(&count); err != nil {
		t.Fatalf("checking audit event: %v", err)
	}
	if count != 1 {
		t.Errorf("audit event count = %d, want exactly 1", count)
	}
}

func TestRecordExpiredAuthorizations_IgnoresUnclaimedAndRevoked(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "postgres", "devpassword")

	appID := insertApplication(t, ctx, conn, "retention-authexpiry2.example.test")

	unclaimedReqID := insertApprovalRequest(t, ctx, conn, appID, "AEXP-0002")
	insertAuthorization(t, ctx, conn, appID, unclaimedReqID, authorizationOpts{ExpiresAt: time.Now().Add(-time.Hour)}) // never activated

	revokedAt := time.Now()
	activatedAt := time.Now().Add(-48 * time.Hour)
	revokedReqID := insertApprovalRequest(t, ctx, conn, appID, "AEXP-0003")
	insertAuthorization(t, ctx, conn, appID, revokedReqID, authorizationOpts{
		ActivatedAt: &activatedAt, ExpiresAt: time.Now().Add(-time.Hour), RevokedAt: &revokedAt,
	})

	n, err := db.RecordExpiredAuthorizations(ctx, 100)
	if err != nil {
		t.Fatalf("RecordExpiredAuthorizations: %v", err)
	}
	if n != 0 {
		t.Errorf("got %d, want 0 (neither authorization qualifies)", n)
	}
}

func TestPurgeExpiredClaimEnvelopes(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "postgres", "devpassword")

	appID := insertApplication(t, ctx, conn, "retention-envelope.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, "ENVP-0001")
	activatedAt := time.Now()
	authID := insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{ActivatedAt: &activatedAt, ExpiresAt: time.Now().Add(30 * 24 * time.Hour)})
	tokenHash := sha256.Sum256([]byte("retention-envelope-token"))
	credID := insertCredential(t, ctx, conn, authID, appID, tokenHash[:], credentialOpts{AbsoluteExpiresAt: time.Now().Add(365 * 24 * time.Hour)})

	var pendingTokenHash []byte
	if err := conn.QueryRow(ctx, `SELECT pending_token_hash FROM approval_requests WHERE id = $1`, reqID).Scan(&pendingTokenHash); err != nil {
		t.Fatalf("reading pending_token_hash: %v", err)
	}
	ecID := uuid.New()
	if _, err := conn.Exec(ctx, `
		INSERT INTO enrollment_contexts (id, application_id, pending_token_hash, csrf_secret, expires_at)
		VALUES ($1, $2, $3, $4, now() + interval '1 hour')`, ecID, appID, pendingTokenHash, make([]byte, 32)); err != nil {
		t.Fatalf("inserting enrollment context: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM enrollment_contexts WHERE id = $1`, ecID) })

	if _, err := conn.Exec(ctx, `
		INSERT INTO claim_results (request_id, credential_id, encryption_key_id, nonce, ciphertext, expires_at)
		VALUES ($1, $2, 'test', $3, $4, now() - interval '1 minute')`, reqID, credID, make([]byte, 12), make([]byte, 16)); err != nil {
		t.Fatalf("inserting claim envelope: %v", err)
	}

	n, err := db.PurgeExpiredClaimEnvelopes(ctx, 100)
	if err != nil {
		t.Fatalf("PurgeExpiredClaimEnvelopes: %v", err)
	}
	if n != 1 {
		t.Errorf("got %d, want 1", n)
	}

	var envelopeCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM claim_results WHERE request_id = $1`, reqID).Scan(&envelopeCount); err != nil {
		t.Fatalf("checking claim_results: %v", err)
	}
	if envelopeCount != 0 {
		t.Error("claim envelope should have been deleted")
	}

	var consumedAt *time.Time
	if err := conn.QueryRow(ctx, `SELECT consumed_at FROM enrollment_contexts WHERE id = $1`, ecID).Scan(&consumedAt); err != nil {
		t.Fatalf("checking enrollment context: %v", err)
	}
	if consumedAt == nil {
		t.Error("enrollment context should be consumed")
	}
}

func TestPurgeExpiredRateLimitBuckets(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO rate_limit_buckets (bucket_key, window_start, count, expires_at)
		VALUES ('retention-test-expired', now() - interval '2 hours', 1, now() - interval '1 hour')`); err != nil {
		t.Fatalf("inserting expired bucket: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO rate_limit_buckets (bucket_key, window_start, count, expires_at)
		VALUES ('retention-test-live', now(), 1, now() + interval '1 hour')`); err != nil {
		t.Fatalf("inserting live bucket: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(ctx, `DELETE FROM rate_limit_buckets WHERE bucket_key IN ('retention-test-expired', 'retention-test-live')`)
	})

	n, err := db.PurgeExpiredRateLimitBuckets(ctx, 100)
	if err != nil {
		t.Fatalf("PurgeExpiredRateLimitBuckets: %v", err)
	}
	if n != 1 {
		t.Errorf("got %d, want 1", n)
	}

	var remaining string
	if err := db.Pool.QueryRow(ctx, `SELECT bucket_key FROM rate_limit_buckets WHERE bucket_key IN ('retention-test-expired', 'retention-test-live')`).Scan(&remaining); err != nil {
		t.Fatalf("checking remaining bucket: %v", err)
	}
	if remaining != "retention-test-live" {
		t.Errorf("remaining bucket = %q, want retention-test-live", remaining)
	}
}

func TestPurgeExpiredIdempotencyRecords(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "postgres", "devpassword")

	tokenHash := sha256.Sum256([]byte("tok-retention"))
	sess, err := db.CreateAdminSession(ctx, "https://idp.example.test/", "retention-user", "", "viewer", tokenHash[:], []byte("secret"), time.Now().Add(8*time.Hour))
	if err != nil {
		t.Fatalf("CreateAdminSession: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM admin_sessions WHERE id = $1`, sess.ID) })

	hash := sha256.Sum256([]byte("body"))
	if _, err := conn.Exec(ctx, `
		INSERT INTO idempotency_records (actor_session_id, key, operation, request_hash, result_status, expires_at)
		VALUES ($1, 'k1', 'op', $2, 200, now() - interval '1 hour')`, sess.ID, hash[:]); err != nil {
		t.Fatalf("inserting expired idempotency record: %v", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO idempotency_records (actor_session_id, key, operation, request_hash, result_status, expires_at)
		VALUES ($1, 'k2', 'op', $2, 200, now() + interval '1 hour')`, sess.ID, hash[:]); err != nil {
		t.Fatalf("inserting live idempotency record: %v", err)
	}

	n, err := db.PurgeExpiredIdempotencyRecords(ctx, 100)
	if err != nil {
		t.Fatalf("PurgeExpiredIdempotencyRecords: %v", err)
	}
	if n != 1 {
		t.Errorf("got %d, want 1", n)
	}

	var remainingKey string
	if err := conn.QueryRow(ctx, `SELECT key FROM idempotency_records WHERE actor_session_id = $1`, sess.ID).Scan(&remainingKey); err != nil {
		t.Fatalf("checking remaining record: %v", err)
	}
	if remainingKey != "k2" {
		t.Errorf("remaining record key = %q, want k2", remainingKey)
	}
}

func TestRedactOldClientMetadata(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "postgres", "devpassword")

	appID := insertApplication(t, ctx, conn, "retention-redact.example.test")
	oldReqID := insertApprovalRequest(t, ctx, conn, appID, "REDT-0001")
	if _, err := conn.Exec(ctx, `
		UPDATE approval_requests SET requested_at = now() - interval '40 days', source_ip = '203.0.113.5', user_agent = 'test-agent'
		WHERE id = $1`, oldReqID); err != nil {
		t.Fatalf("backdating request: %v", err)
	}
	newReqID := insertApprovalRequest(t, ctx, conn, appID, "REDT-0002")
	if _, err := conn.Exec(ctx, `UPDATE approval_requests SET source_ip = '203.0.113.6', user_agent = 'test-agent' WHERE id = $1`, newReqID); err != nil {
		t.Fatalf("setting metadata on new request: %v", err)
	}

	activatedAt := time.Now()
	authID := insertAuthorization(t, ctx, conn, appID, newReqID, authorizationOpts{ActivatedAt: &activatedAt, ExpiresAt: time.Now().Add(30 * 24 * time.Hour)})
	if _, err := conn.Exec(ctx, `
		UPDATE authorizations SET last_seen_at = now() - interval '40 days', last_seen_ip = '203.0.113.7', last_seen_user_agent = 'test-agent'
		WHERE id = $1`, authID); err != nil {
		t.Fatalf("backdating authorization last-seen: %v", err)
	}

	n, err := db.RedactOldClientMetadata(ctx, 30*24*time.Hour, 100)
	if err != nil {
		t.Fatalf("RedactOldClientMetadata: %v", err)
	}
	if n != 2 {
		t.Errorf("got %d rows redacted, want 2 (one request, one authorization)", n)
	}

	var sourceIP, userAgent *string
	if err := conn.QueryRow(ctx, `SELECT source_ip::text, user_agent FROM approval_requests WHERE id = $1`, oldReqID).Scan(&sourceIP, &userAgent); err != nil {
		t.Fatalf("checking old request: %v", err)
	}
	if sourceIP != nil || userAgent != nil {
		t.Errorf("old request metadata = (%v, %v), want both nil", sourceIP, userAgent)
	}

	if err := conn.QueryRow(ctx, `SELECT source_ip::text, user_agent FROM approval_requests WHERE id = $1`, newReqID).Scan(&sourceIP, &userAgent); err != nil {
		t.Fatalf("checking new request: %v", err)
	}
	if sourceIP == nil || userAgent == nil {
		t.Error("new request metadata should be untouched")
	}

	var lastSeenIP, lastSeenUA *string
	if err := conn.QueryRow(ctx, `SELECT last_seen_ip::text, last_seen_user_agent FROM authorizations WHERE id = $1`, authID).Scan(&lastSeenIP, &lastSeenUA); err != nil {
		t.Fatalf("checking authorization: %v", err)
	}
	if lastSeenIP != nil || lastSeenUA != nil {
		t.Errorf("authorization last-seen metadata = (%v, %v), want both nil", lastSeenIP, lastSeenUA)
	}
}

func TestRedactOldReturnPaths(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "postgres", "devpassword")

	appID := insertApplication(t, ctx, conn, "retention-returnpath.example.test")
	oldReqID := insertApprovalRequest(t, ctx, conn, appID, "RPTH-0001")
	if _, err := conn.Exec(ctx, `
		UPDATE approval_requests SET requested_at = now() - interval '10 days', return_path = '/dashboard'
		WHERE id = $1`, oldReqID); err != nil {
		t.Fatalf("backdating request: %v", err)
	}
	newReqID := insertApprovalRequest(t, ctx, conn, appID, "RPTH-0002")
	if _, err := conn.Exec(ctx, `UPDATE approval_requests SET return_path = '/dashboard' WHERE id = $1`, newReqID); err != nil {
		t.Fatalf("setting return_path on new request: %v", err)
	}

	n, err := db.RedactOldReturnPaths(ctx, 7*24*time.Hour, 100)
	if err != nil {
		t.Fatalf("RedactOldReturnPaths: %v", err)
	}
	if n != 1 {
		t.Errorf("got %d, want 1", n)
	}

	var returnPath *string
	if err := conn.QueryRow(ctx, `SELECT return_path FROM approval_requests WHERE id = $1`, oldReqID).Scan(&returnPath); err != nil {
		t.Fatalf("checking old request: %v", err)
	}
	if returnPath != nil {
		t.Errorf("old request return_path = %v, want nil", returnPath)
	}
	if err := conn.QueryRow(ctx, `SELECT return_path FROM approval_requests WHERE id = $1`, newReqID).Scan(&returnPath); err != nil {
		t.Fatalf("checking new request: %v", err)
	}
	if returnPath == nil {
		t.Error("new request return_path should be untouched")
	}
}

// TestPurgeResolvedRecords_NeverPurgesALiveAuthorization is the safety-
// critical case: no matter how old a 'claimed' request's decided_at is,
// its row (and its authorization/credential) must survive as long as
// the authorization itself is still live -- ForwardAuth's authoritative
// check depends on that row existing.
func TestPurgeResolvedRecords_NeverPurgesALiveAuthorization(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "postgres", "devpassword")

	appID := insertApplication(t, ctx, conn, "retention-live.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, "LIVE-0001")
	if _, err := conn.Exec(ctx, `
		UPDATE approval_requests SET status = 'claimed', decided_at = now() - interval '200 days', claimed_at = now() - interval '200 days'
		WHERE id = $1`, reqID); err != nil {
		t.Fatalf("marking request claimed long ago: %v", err)
	}
	activatedAt := time.Now().Add(-200 * 24 * time.Hour)
	authID := insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{
		ActivatedAt: &activatedAt, ExpiresAt: time.Now().Add(24 * time.Hour), // still live
	})
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM authorizations WHERE id = $1`, authID) })

	n, err := db.PurgeResolvedRecords(ctx, 90*24*time.Hour, 100)
	if err != nil {
		t.Fatalf("PurgeResolvedRecords: %v", err)
	}
	if n != 0 {
		t.Fatalf("got %d purged, want 0 -- a live authorization must never be purged", n)
	}

	var stillThere int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM approval_requests WHERE id = $1`, reqID).Scan(&stillThere); err != nil {
		t.Fatalf("checking request survives: %v", err)
	}
	if stillThere != 1 {
		t.Error("request should still exist")
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM authorizations WHERE id = $1`, authID).Scan(&stillThere); err != nil {
		t.Fatalf("checking authorization survives: %v", err)
	}
	if stillThere != 1 {
		t.Error("authorization should still exist")
	}
}

func TestPurgeResolvedRecords_PurgesTerminalRecords(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "postgres", "devpassword")

	appID := insertApplication(t, ctx, conn, "retention-resolved.example.test")

	// Denied: never had an authorization.
	deniedID := insertApprovalRequest(t, ctx, conn, appID, "RSLV-0001")
	if _, err := conn.Exec(ctx, `UPDATE approval_requests SET status = 'denied', decided_at = now() - interval '100 days' WHERE id = $1`, deniedID); err != nil {
		t.Fatalf("marking request denied: %v", err)
	}

	// Claimed, but its authorization expired long ago and was never renewed.
	expiredID := insertApprovalRequest(t, ctx, conn, appID, "RSLV-0002")
	if _, err := conn.Exec(ctx, `UPDATE approval_requests SET status = 'claimed', decided_at = now() - interval '100 days' WHERE id = $1`, expiredID); err != nil {
		t.Fatalf("marking request claimed: %v", err)
	}
	activatedAt := time.Now().Add(-100 * 24 * time.Hour)
	expiredAuthID := insertAuthorization(t, ctx, conn, appID, expiredID, authorizationOpts{
		ActivatedAt: &activatedAt, ExpiresAt: time.Now().Add(-95 * 24 * time.Hour),
	})
	tokenHash := sha256.Sum256([]byte("resolved-records-token"))
	credID := insertCredential(t, ctx, conn, expiredAuthID, appID, tokenHash[:], credentialOpts{AbsoluteExpiresAt: time.Now().Add(-1 * time.Hour)})

	n, err := db.PurgeResolvedRecords(ctx, 90*24*time.Hour, 100)
	if err != nil {
		t.Fatalf("PurgeResolvedRecords: %v", err)
	}
	if n != 2 {
		t.Errorf("got %d purged, want 2", n)
	}

	for _, id := range []string{deniedID, expiredID} {
		var count int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM approval_requests WHERE id = $1`, id).Scan(&count); err != nil {
			t.Fatalf("checking request %s purged: %v", id, err)
		}
		if count != 0 {
			t.Errorf("request %s should have been purged", id)
		}
	}
	var authCount, credCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM authorizations WHERE id = $1`, expiredAuthID).Scan(&authCount); err != nil {
		t.Fatalf("checking authorization purged: %v", err)
	}
	if authCount != 0 {
		t.Error("authorization should have been purged")
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE id = $1`, credID).Scan(&credCount); err != nil {
		t.Fatalf("checking credential purged: %v", err)
	}
	if credCount != 0 {
		t.Error("credential should have been purged")
	}
}

func TestPurgeOldAuditEvents(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	// PurgeOldAuditEvents requires the app_maintenance role -- app_runtime
	// deliberately has no DELETE on audit_events (spec section 11,
	// control 10).
	db := openStoreAs(t, ctx, dbURL, "approve_auth_maintenance", "devpassword")
	conn := connectAs(t, ctx, dbURL, "postgres", "devpassword")

	oldID := uuid.New()
	if _, err := conn.Exec(ctx, `
		INSERT INTO audit_events (id, occurred_at, actor_type, action, correlation_id, outcome)
		VALUES ($1, now() - interval '400 days', 'system', 'test.old', gen_random_uuid(), 'success')`, oldID); err != nil {
		t.Fatalf("inserting old audit event: %v", err)
	}
	recentID := uuid.New()
	if _, err := conn.Exec(ctx, `
		INSERT INTO audit_events (id, occurred_at, actor_type, action, correlation_id, outcome)
		VALUES ($1, now() - interval '1 day', 'system', 'test.recent', gen_random_uuid(), 'success')`, recentID); err != nil {
		t.Fatalf("inserting recent audit event: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM audit_events WHERE id IN ($1, $2)`, oldID, recentID) })

	n, err := db.PurgeOldAuditEvents(ctx, 365*24*time.Hour, 1000)
	if err != nil {
		t.Fatalf("PurgeOldAuditEvents: %v", err)
	}
	if n < 1 {
		t.Errorf("got %d, want at least 1", n)
	}

	var oldCount, recentCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE id = $1`, oldID).Scan(&oldCount); err != nil {
		t.Fatalf("checking old event: %v", err)
	}
	if oldCount != 0 {
		t.Error("old audit event should have been purged")
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE id = $1`, recentID).Scan(&recentCount); err != nil {
		t.Fatalf("checking recent event: %v", err)
	}
	if recentCount != 1 {
		t.Error("recent audit event should survive")
	}
}
