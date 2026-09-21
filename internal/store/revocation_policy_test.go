package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/paxanimae/approve-auth/internal/revokepolicy"
)

func TestFlagAuthorizationForReview_SetsFlagAndIsIdempotent(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "flag-review.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, t.Name())
	authIDStr := insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{ExpiresAt: time.Now().Add(30 * 24 * time.Hour)})
	authID := mustParseUUID(t, authIDStr)
	applicationID := mustParseUUID(t, appID)

	if err := db.FlagAuthorizationForReview(ctx, authID, applicationID, "ip_changed"); err != nil {
		t.Fatalf("FlagAuthorizationForReview: %v", err)
	}

	var flaggedAt *time.Time
	var flaggedReason *string
	if err := conn.QueryRow(ctx, `SELECT flagged_at, flagged_reason FROM authorizations WHERE id = $1`, authIDStr).Scan(&flaggedAt, &flaggedReason); err != nil {
		t.Fatalf("querying flagged_at: %v", err)
	}
	if flaggedAt == nil {
		t.Fatal("expected flagged_at to be set")
	}
	if flaggedReason == nil || *flaggedReason != "ip_changed" {
		t.Errorf("flagged_reason = %v, want ip_changed", flaggedReason)
	}
	firstFlaggedAt := *flaggedAt

	// Flagging an already-flagged authorization must be a no-op --
	// flagged_at must not move forward, and no second audit event.
	if err := db.FlagAuthorizationForReview(ctx, authID, applicationID, "user_agent_changed"); err != nil {
		t.Fatalf("FlagAuthorizationForReview (repeat): %v", err)
	}
	var secondFlaggedAt time.Time
	if err := conn.QueryRow(ctx, `SELECT flagged_at FROM authorizations WHERE id = $1`, authIDStr).Scan(&secondFlaggedAt); err != nil {
		t.Fatalf("querying flagged_at (second): %v", err)
	}
	if !secondFlaggedAt.Equal(firstFlaggedAt) {
		t.Errorf("flagged_at changed on a repeat call: %s -> %s", firstFlaggedAt, secondFlaggedAt)
	}

	var auditCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE authorization_id = $1 AND action = 'authorization.flagged_for_review'`, authIDStr).Scan(&auditCount); err != nil {
		t.Fatalf("counting audit events: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("audit event count = %d, want exactly 1", auditCount)
	}
}

func TestClearAuthorizationFlag_ClearsAndIsIdempotentWhenNotFlagged(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "clear-flag.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, t.Name())
	authIDStr := insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{ExpiresAt: time.Now().Add(30 * 24 * time.Hour)})
	authID := mustParseUUID(t, authIDStr)
	applicationID := mustParseUUID(t, appID)

	// Clearing an authorization that was never flagged must be a no-op,
	// not an error.
	if err := db.ClearAuthorizationFlag(ctx, authID, "admin@example.test"); err != nil {
		t.Fatalf("ClearAuthorizationFlag (never flagged): %v", err)
	}

	if err := db.FlagAuthorizationForReview(ctx, authID, applicationID, "ip_changed"); err != nil {
		t.Fatalf("FlagAuthorizationForReview: %v", err)
	}
	if err := db.ClearAuthorizationFlag(ctx, authID, "admin@example.test"); err != nil {
		t.Fatalf("ClearAuthorizationFlag: %v", err)
	}

	var flaggedAt *time.Time
	var flaggedReason *string
	if err := conn.QueryRow(ctx, `SELECT flagged_at, flagged_reason FROM authorizations WHERE id = $1`, authIDStr).Scan(&flaggedAt, &flaggedReason); err != nil {
		t.Fatalf("querying flagged_at: %v", err)
	}
	if flaggedAt != nil || flaggedReason != nil {
		t.Errorf("flagged_at/flagged_reason = %v/%v, want both nil after clearing", flaggedAt, flaggedReason)
	}

	var auditCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE authorization_id = $1 AND action = 'authorization.flag_cleared'`, authIDStr).Scan(&auditCount); err != nil {
		t.Fatalf("counting audit events: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("audit event count = %d, want exactly 1", auditCount)
	}
}

func TestRecordRevocationPolicyWarning_WritesAuditEvent(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "policy-warning.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, t.Name())
	authIDStr := insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{ExpiresAt: time.Now().Add(30 * 24 * time.Hour)})
	authID := mustParseUUID(t, authIDStr)
	applicationID := mustParseUUID(t, appID)

	if err := db.RecordRevocationPolicyWarning(ctx, authID, applicationID, "ip_changed"); err != nil {
		t.Fatalf("RecordRevocationPolicyWarning: %v", err)
	}
	// Firing twice must produce two rows -- warn is deliberately not
	// deduplicated (see the store method's own comment).
	if err := db.RecordRevocationPolicyWarning(ctx, authID, applicationID, "ip_changed"); err != nil {
		t.Fatalf("RecordRevocationPolicyWarning (second): %v", err)
	}

	var auditCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE authorization_id = $1 AND action = 'authorization.policy_warning'`, authIDStr).Scan(&auditCount); err != nil {
		t.Fatalf("counting audit events: %v", err)
	}
	if auditCount != 2 {
		t.Errorf("audit event count = %d, want exactly 2 (warn is not deduplicated)", auditCount)
	}
}

func TestEnforceInactivityPolicy_RevokesWarnsAndFlagsByResolvedAction(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "inactivity.example.test")

	// One authorization per resolved action, each backdated well past
	// the threshold this test uses.
	mkInactive := func(name string) (authIDStr string) {
		reqID := insertApprovalRequest(t, ctx, conn, appID, name)
		activatedAt := time.Now().Add(-100 * 24 * time.Hour)
		authIDStr = insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{
			ExpiresAt:   time.Now().Add(365 * 24 * time.Hour),
			ActivatedAt: &activatedAt,
		})
		if _, err := conn.Exec(ctx, `UPDATE authorizations SET approved_at = $2 WHERE id = $1`, authIDStr, activatedAt); err != nil {
			t.Fatalf("backdating approved_at: %v", err)
		}
		return authIDStr
	}

	revokeID := mkInactive("inactivity-revoke")
	warnID := mkInactive("inactivity-warn")
	flagID := mkInactive("inactivity-flag")
	offID := mkInactive("inactivity-off")

	if _, err := conn.Exec(ctx, `UPDATE authorizations SET revoke_policy_inactivity_exceeded = 'revoke' WHERE id = $1`, revokeID); err != nil {
		t.Fatalf("setting per-session override: %v", err)
	}
	if _, err := conn.Exec(ctx, `UPDATE authorizations SET revoke_policy_inactivity_exceeded = 'warn' WHERE id = $1`, warnID); err != nil {
		t.Fatalf("setting per-session override: %v", err)
	}
	if _, err := conn.Exec(ctx, `UPDATE authorizations SET revoke_policy_inactivity_exceeded = 'flag_for_review' WHERE id = $1`, flagID); err != nil {
		t.Fatalf("setting per-session override: %v", err)
	}
	if _, err := conn.Exec(ctx, `UPDATE authorizations SET revoke_policy_inactivity_exceeded = 'off' WHERE id = $1`, offID); err != nil {
		t.Fatalf("setting per-session override: %v", err)
	}

	// Global default doesn't matter here since every candidate has its
	// own explicit session override -- pass "off" to prove that.
	affected, err := db.EnforceInactivityPolicy(ctx, revokepolicy.ActionOff, 24*time.Hour, 100)
	if err != nil {
		t.Fatalf("EnforceInactivityPolicy: %v", err)
	}
	if affected < 3 {
		t.Errorf("affected = %d, want at least 3 (revoke, warn, flag)", affected)
	}

	var revokedAt *time.Time
	if err := conn.QueryRow(ctx, `SELECT revoked_at FROM authorizations WHERE id = $1`, revokeID).Scan(&revokedAt); err != nil {
		t.Fatalf("querying revoked_at: %v", err)
	}
	if revokedAt == nil {
		t.Error("expected the revoke-configured authorization to be revoked")
	}

	var warnAuditCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE authorization_id = $1 AND action = 'authorization.inactivity_warned'`, warnID).Scan(&warnAuditCount); err != nil {
		t.Fatalf("counting warn audit events: %v", err)
	}
	if warnAuditCount != 1 {
		t.Errorf("warn audit event count = %d, want exactly 1", warnAuditCount)
	}

	var flaggedAt *time.Time
	if err := conn.QueryRow(ctx, `SELECT flagged_at FROM authorizations WHERE id = $1`, flagID).Scan(&flaggedAt); err != nil {
		t.Fatalf("querying flagged_at: %v", err)
	}
	if flaggedAt == nil {
		t.Error("expected the flag_for_review-configured authorization to be flagged")
	}

	var offRevokedAt *time.Time
	var offFlaggedAt *time.Time
	if err := conn.QueryRow(ctx, `SELECT revoked_at, flagged_at FROM authorizations WHERE id = $1`, offID).Scan(&offRevokedAt, &offFlaggedAt); err != nil {
		t.Fatalf("querying off-configured authorization: %v", err)
	}
	if offRevokedAt != nil || offFlaggedAt != nil {
		t.Error("the off-configured authorization must be left completely untouched")
	}

	// A second run must not re-warn (idempotent per inactivity episode)
	// or double-revoke/double-flag.
	if _, err := db.EnforceInactivityPolicy(ctx, revokepolicy.ActionOff, 24*time.Hour, 100); err != nil {
		t.Fatalf("EnforceInactivityPolicy (second run): %v", err)
	}
	var warnAuditCountAfterSecondRun int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE authorization_id = $1 AND action = 'authorization.inactivity_warned'`, warnID).Scan(&warnAuditCountAfterSecondRun); err != nil {
		t.Fatalf("counting warn audit events (second run): %v", err)
	}
	if warnAuditCountAfterSecondRun != 1 {
		t.Errorf("warn audit event count after a second run = %d, want still exactly 1 (idempotent per episode)", warnAuditCountAfterSecondRun)
	}
}

func TestEnforceInactivityPolicy_IgnoresAuthorizationsWithinThreshold(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "inactivity-recent.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, t.Name())
	activatedAt := time.Now().Add(-time.Hour)
	authIDStr := insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour),
		ActivatedAt: &activatedAt,
	})
	if _, err := conn.Exec(ctx, `UPDATE authorizations SET revoke_policy_inactivity_exceeded = 'revoke' WHERE id = $1`, authIDStr); err != nil {
		t.Fatalf("setting per-session override: %v", err)
	}

	if _, err := db.EnforceInactivityPolicy(ctx, revokepolicy.ActionOff, 24*time.Hour, 100); err != nil {
		t.Fatalf("EnforceInactivityPolicy: %v", err)
	}

	var revokedAt *time.Time
	if err := conn.QueryRow(ctx, `SELECT revoked_at FROM authorizations WHERE id = $1`, authIDStr).Scan(&revokedAt); err != nil {
		t.Fatalf("querying revoked_at: %v", err)
	}
	if revokedAt != nil {
		t.Error("an authorization active within the threshold must not be touched")
	}
}
