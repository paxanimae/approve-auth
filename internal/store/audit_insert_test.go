package store_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/frid-iks/approve-auth/internal/store"
)

// TestMutationsWriteAuditEvents confirms spec section 12's "mutations
// fail if their audit event cannot commit" is actually wired up, not
// just non-regressing: every mutation in the approve -> claim -> renew
// -> revoke chain, plus deny and cancel, must leave a matching row.
func TestMutationsWriteAuditEvents(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	maintenance := connectAs(t, ctx, dbURL, "approve_auth_maintenance", "devpassword")

	countActions := func(t *testing.T, requestID string) map[string]int {
		t.Helper()
		rows, err := conn.Query(ctx, `SELECT action FROM audit_events WHERE request_id = $1`, requestID)
		if err != nil {
			t.Fatalf("querying audit_events: %v", err)
		}
		defer rows.Close()
		counts := map[string]int{}
		for rows.Next() {
			var action string
			if err := rows.Scan(&action); err != nil {
				t.Fatalf("scanning action: %v", err)
			}
			counts[action]++
		}
		return counts
	}

	appID := insertApplication(t, ctx, conn, "audit-events.example.test")
	appUUID := mustParseUUID(t, appID)

	pendingHash := sha256.Sum256([]byte(t.Name() + ":approve-chain"))
	req, err := db.CreateApprovalRequest(ctx, store.CreateApprovalRequestParams{
		ApplicationID: appUUID, PendingTokenHash: pendingHash[:], VerificationCode: "AUDIT001", DeadlineAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}
	t.Cleanup(func() {
		_, _ = maintenance.Exec(ctx, `DELETE FROM audit_events WHERE request_id = $1`, req.ID)
		_, _ = conn.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, req.ID)
	})
	if counts := countActions(t, req.ID.String()); counts["request.created"] != 1 {
		t.Errorf("after CreateApprovalRequest: counts = %v, want request.created=1", counts)
	}

	auth, err := db.ApproveRequest(ctx, req.ID, req.Version, time.Now().Add(30*24*time.Hour), 30*time.Minute, "", "", "admin@example.test", nil, nil, nil)
	if err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM authorizations WHERE id = $1`, auth.ID) })
	if counts := countActions(t, req.ID.String()); counts["request.approved"] != 1 {
		t.Errorf("after ApproveRequest: counts = %v, want request.approved=1", counts)
	}

	rawToken := "audit-test-token-" + t.Name()
	tokenHash := sha256.Sum256([]byte(rawToken))
	credentialID, _, _, err := db.ClaimApproved(ctx, req.ID, tokenHash[:], 365*24*time.Hour)
	if err != nil {
		t.Fatalf("ClaimApproved: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM credentials WHERE id = $1`, credentialID) })
	if counts := countActions(t, req.ID.String()); counts["claim.completed"] != 1 {
		t.Errorf("after ClaimApproved: counts = %v, want claim.completed=1", counts)
	}

	authAfterClaim, ok, err := db.GetAuthorizationByID(ctx, auth.ID)
	if err != nil || !ok {
		t.Fatalf("GetAuthorizationByID: ok=%v err=%v", ok, err)
	}
	if err := db.RenewAuthorization(ctx, auth.ID, authAfterClaim.Version, authAfterClaim.ExpiresAt.Add(7*24*time.Hour), "admin@example.test"); err != nil {
		t.Fatalf("RenewAuthorization: %v", err)
	}
	if counts := countActions(t, req.ID.String()); counts["authorization.renewed"] != 1 {
		t.Errorf("after RenewAuthorization: counts = %v, want authorization.renewed=1", counts)
	}

	renewed, ok, err := db.GetAuthorizationByID(ctx, auth.ID)
	if err != nil || !ok {
		t.Fatalf("GetAuthorizationByID: ok=%v err=%v", ok, err)
	}
	if err := db.RevokeAuthorization(ctx, auth.ID, renewed.Version, "done testing", "admin@example.test"); err != nil {
		t.Fatalf("RevokeAuthorization: %v", err)
	}
	if counts := countActions(t, req.ID.String()); counts["authorization.revoked"] != 1 {
		t.Errorf("after RevokeAuthorization: counts = %v, want authorization.revoked=1", counts)
	}

	// Deny and cancel on separate fresh requests (each only valid from "pending").
	denyHash := sha256.Sum256([]byte(t.Name() + ":deny"))
	denyReq, err := db.CreateApprovalRequest(ctx, store.CreateApprovalRequestParams{
		ApplicationID: appUUID, PendingTokenHash: denyHash[:], VerificationCode: "AUDIT002", DeadlineAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}
	t.Cleanup(func() {
		_, _ = maintenance.Exec(ctx, `DELETE FROM audit_events WHERE request_id = $1`, denyReq.ID)
		_, _ = conn.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, denyReq.ID)
	})
	if err := db.DenyRequest(ctx, denyReq.ID, denyReq.Version, "no", "", "admin@example.test"); err != nil {
		t.Fatalf("DenyRequest: %v", err)
	}
	if counts := countActions(t, denyReq.ID.String()); counts["request.denied"] != 1 {
		t.Errorf("after DenyRequest: counts = %v, want request.denied=1", counts)
	}

	cancelHash := sha256.Sum256([]byte(t.Name() + ":cancel"))
	cancelReq, err := db.CreateApprovalRequest(ctx, store.CreateApprovalRequestParams{
		ApplicationID: appUUID, PendingTokenHash: cancelHash[:], VerificationCode: "AUDIT003", DeadlineAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}
	t.Cleanup(func() {
		_, _ = maintenance.Exec(ctx, `DELETE FROM audit_events WHERE request_id = $1`, cancelReq.ID)
		_, _ = conn.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, cancelReq.ID)
	})
	if err := db.CancelApprovalRequest(ctx, cancelReq.ID); err != nil {
		t.Fatalf("CancelApprovalRequest: %v", err)
	}
	if counts := countActions(t, cancelReq.ID.String()); counts["request.canceled"] != 1 {
		t.Errorf("after CancelApprovalRequest: counts = %v, want request.canceled=1", counts)
	}
}
