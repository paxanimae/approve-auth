package store_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/frid-iks/traefik-manual-proxy/internal/store"
)

func TestLifecycle_EnrollmentContext(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "manual_approval_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "lifecycle-enrollment.example.test")
	appUUID := mustParseUUID(t, appID)
	hash := sha256.Sum256([]byte(t.Name()))

	ec, err := db.CreateEnrollmentContext(ctx, appUUID, hash[:], []byte("csrf-secret-bytes"), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CreateEnrollmentContext: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM enrollment_contexts WHERE id = $1`, ec.ID) })

	found, ok, err := db.GetLiveEnrollmentContextByTokenHash(ctx, hash[:])
	if err != nil {
		t.Fatalf("GetLiveEnrollmentContextByTokenHash: %v", err)
	}
	if !ok || found.ID != ec.ID {
		t.Fatalf("expected to find the just-created context, got ok=%v found=%+v", ok, found)
	}

	if err := db.ConsumeEnrollmentContext(ctx, ec.ID); err != nil {
		t.Fatalf("ConsumeEnrollmentContext: %v", err)
	}
	_, ok, err = db.GetLiveEnrollmentContextByTokenHash(ctx, hash[:])
	if err != nil {
		t.Fatalf("GetLiveEnrollmentContextByTokenHash (after consume): %v", err)
	}
	if ok {
		t.Error("expected a consumed context to no longer be 'live'")
	}
}

func TestLifecycle_ApproveClaimRenewRevoke(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "manual_approval_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "lifecycle-approve.example.test")
	appUUID := mustParseUUID(t, appID)
	pendingHash := sha256.Sum256([]byte(t.Name()))

	req, err := db.CreateApprovalRequest(ctx, store.CreateApprovalRequestParams{
		ApplicationID:    appUUID,
		PendingTokenHash: pendingHash[:],
		VerificationCode: "LIFE-0001",
		DeadlineAt:       time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, req.ID) })

	got, ok, err := db.GetApprovalRequestByTokenHash(ctx, pendingHash[:])
	if err != nil {
		t.Fatalf("GetApprovalRequestByTokenHash: %v", err)
	}
	if !ok || got.ID != req.ID || got.Status != "pending" {
		t.Fatalf("unexpected lookup result: ok=%v got=%+v", ok, got)
	}

	auth, err := db.ApproveRequest(ctx, req.ID, req.Version, time.Now().Add(30*24*time.Hour), 30*time.Minute, "my-tv", "looked legit", "admin@example.test")
	if err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM authorizations WHERE id = $1`, auth.ID) })
	if auth.ActivatedAt != nil {
		t.Error("a freshly approved authorization must not be activated yet (unclaimed)")
	}

	// Re-approving the same (now stale-version) request must conflict.
	if _, err := db.ApproveRequest(ctx, req.ID, req.Version, time.Now().Add(30*24*time.Hour), 30*time.Minute, "", "", "admin@example.test"); err != store.ErrConflict {
		t.Errorf("re-approving: got %v, want ErrConflict", err)
	}

	rawToken := "raw-token-" + t.Name()
	tokenHash := sha256.Sum256([]byte(rawToken))
	credentialID, applicationID, alreadyClaimed, err := db.ClaimApproved(ctx, req.ID, tokenHash[:], 365*24*time.Hour)
	if err != nil {
		t.Fatalf("ClaimApproved: %v", err)
	}
	if alreadyClaimed {
		t.Fatal("first claim should not report alreadyClaimed")
	}
	if applicationID != appUUID {
		t.Errorf("ClaimApproved applicationID = %s, want %s", applicationID, appUUID)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM credentials WHERE id = $1`, credentialID) })

	if err := db.SaveClaimEnvelope(ctx, req.ID, credentialID, "test-key", []byte("nonce"), []byte("ciphertext"), time.Now().Add(10*time.Minute)); err != nil {
		t.Fatalf("SaveClaimEnvelope: %v", err)
	}
	t.Cleanup(func() { _ = db.DeleteClaimEnvelope(ctx, req.ID) })

	envelope, ok, err := db.GetLiveClaimEnvelope(ctx, req.ID)
	if err != nil {
		t.Fatalf("GetLiveClaimEnvelope: %v", err)
	}
	if !ok || envelope.CredentialID != credentialID {
		t.Fatalf("unexpected envelope: ok=%v envelope=%+v", ok, envelope)
	}

	// Retry: claiming again with a *different* candidate token must
	// report alreadyClaimed and must NOT create a second credential.
	retryHash := sha256.Sum256([]byte("a-different-candidate-token"))
	_, _, alreadyClaimed, err = db.ClaimApproved(ctx, req.ID, retryHash[:], 365*24*time.Hour)
	if err != nil {
		t.Fatalf("ClaimApproved (retry): %v", err)
	}
	if !alreadyClaimed {
		t.Error("retry claim should report alreadyClaimed=true")
	}
	var credentialCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE authorization_id = $1`, auth.ID).Scan(&credentialCount); err != nil {
		t.Fatalf("counting credentials: %v", err)
	}
	if credentialCount != 1 {
		t.Errorf("credential count after retry = %d, want 1 (no second credential created)", credentialCount)
	}

	if err := db.DeleteClaimEnvelope(ctx, req.ID); err != nil {
		t.Fatalf("DeleteClaimEnvelope: %v", err)
	}
	if _, ok, err := db.GetLiveClaimEnvelope(ctx, req.ID); err != nil || ok {
		t.Errorf("after delete: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	// Renew: must succeed within the credential's absolute ceiling.
	authAfterClaim, ok, err := db.GetAuthorizationByID(ctx, auth.ID)
	if err != nil || !ok {
		t.Fatalf("GetAuthorizationByID: ok=%v err=%v", ok, err)
	}
	newExpiry := authAfterClaim.ExpiresAt.Add(7 * 24 * time.Hour)
	if err := db.RenewAuthorization(ctx, auth.ID, authAfterClaim.Version, newExpiry, "admin@example.test"); err != nil {
		t.Fatalf("RenewAuthorization: %v", err)
	}

	// Renewing past the credential's absolute ceiling must conflict.
	renewed, ok, err := db.GetAuthorizationByID(ctx, auth.ID)
	if err != nil || !ok {
		t.Fatalf("GetAuthorizationByID (after renew): ok=%v err=%v", ok, err)
	}
	if err := db.RenewAuthorization(ctx, auth.ID, renewed.Version, time.Now().Add(1000*24*time.Hour), "admin@example.test"); err != store.ErrConflict {
		t.Errorf("renewing past the credential ceiling: got %v, want ErrConflict", err)
	}

	if err := db.RevokeAuthorization(ctx, auth.ID, renewed.Version, "test done", "admin@example.test"); err != nil {
		t.Fatalf("RevokeAuthorization: %v", err)
	}
	revoked, ok, err := db.GetAuthorizationByID(ctx, auth.ID)
	if err != nil || !ok {
		t.Fatalf("GetAuthorizationByID (after revoke): ok=%v err=%v", ok, err)
	}
	if revoked.RevokedAt == nil {
		t.Error("expected RevokedAt to be set after RevokeAuthorization")
	}

	// Revoking an already-revoked authorization must conflict, not
	// silently succeed a second time.
	if err := db.RevokeAuthorization(ctx, auth.ID, revoked.Version, "again", "admin@example.test"); err != store.ErrConflict {
		t.Errorf("double revoke: got %v, want ErrConflict", err)
	}
}

func TestLifecycle_DenyAndCancel(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "manual_approval_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "lifecycle-deny.example.test")
	appUUID := mustParseUUID(t, appID)

	denyHash := sha256.Sum256([]byte(t.Name() + ":deny"))
	denyEC, err := db.CreateEnrollmentContext(ctx, appUUID, denyHash[:], []byte("csrf-secret-bytes"), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CreateEnrollmentContext: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM enrollment_contexts WHERE id = $1`, denyEC.ID) })
	denyReq, err := db.CreateApprovalRequest(ctx, store.CreateApprovalRequestParams{
		ApplicationID: appUUID, PendingTokenHash: denyHash[:], VerificationCode: "LIFE-0002", DeadlineAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, denyReq.ID) })

	if err := db.DenyRequest(ctx, denyReq.ID, denyReq.Version, "no thanks", "denied by policy", "admin@example.test"); err != nil {
		t.Fatalf("DenyRequest: %v", err)
	}
	afterDeny, ok, err := db.GetApprovalRequestByTokenHash(ctx, denyHash[:])
	if err != nil || !ok {
		t.Fatalf("GetApprovalRequestByTokenHash: ok=%v err=%v", ok, err)
	}
	if afterDeny.Status != "denied" {
		t.Errorf("Status = %q, want denied", afterDeny.Status)
	}
	// Regression: a denied request's enrollment context must also be
	// consumed, or a browser that still has this pending cookie would
	// reuse this same dead context on its next visit to the request
	// page and collide with this denied row instead of starting fresh
	// (see DenyRequest's doc comment).
	if _, stillLive, err := db.GetLiveEnrollmentContextByTokenHash(ctx, denyHash[:]); err != nil {
		t.Fatalf("GetLiveEnrollmentContextByTokenHash: %v", err)
	} else if stillLive {
		t.Error("expected the denied request's enrollment context to be consumed, but it's still live")
	}

	// Denying an already-decided request must conflict.
	if err := db.DenyRequest(ctx, denyReq.ID, afterDeny.Version, "again", "", "admin@example.test"); err != store.ErrConflict {
		t.Errorf("double deny: got %v, want ErrConflict", err)
	}

	cancelHash := sha256.Sum256([]byte(t.Name() + ":cancel"))
	cancelEC, err := db.CreateEnrollmentContext(ctx, appUUID, cancelHash[:], []byte("csrf-secret-bytes"), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CreateEnrollmentContext: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM enrollment_contexts WHERE id = $1`, cancelEC.ID) })
	cancelReq, err := db.CreateApprovalRequest(ctx, store.CreateApprovalRequestParams{
		ApplicationID: appUUID, PendingTokenHash: cancelHash[:], VerificationCode: "LIFE-0003", DeadlineAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, cancelReq.ID) })

	if err := db.CancelApprovalRequest(ctx, cancelReq.ID); err != nil {
		t.Fatalf("CancelApprovalRequest: %v", err)
	}
	afterCancel, ok, err := db.GetApprovalRequestByTokenHash(ctx, cancelHash[:])
	if err != nil || !ok {
		t.Fatalf("GetApprovalRequestByTokenHash: ok=%v err=%v", ok, err)
	}
	if afterCancel.Status != "canceled" {
		t.Errorf("Status = %q, want canceled", afterCancel.Status)
	}
	// Regression: see the same assertion above for DenyRequest -- a
	// canceled request's enrollment context must also be consumed (this
	// is the exact bug a user hit: cancel, then submit a fresh manual
	// request with a message, and land back on "Request canceled"
	// because the browser's still-live pending cookie reused this same
	// context and collided with this canceled row).
	if _, stillLive, err := db.GetLiveEnrollmentContextByTokenHash(ctx, cancelHash[:]); err != nil {
		t.Fatalf("GetLiveEnrollmentContextByTokenHash: %v", err)
	} else if stillLive {
		t.Error("expected the canceled request's enrollment context to be consumed, but it's still live")
	}
}
