package store_test

import (
	"context"
	"testing"
	"time"
)

func TestGetOverviewCounts(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "postgres", "devpassword")

	appID := insertApplication(t, ctx, conn, "overview.example.test")

	pendingReqID := insertApprovalRequest(t, ctx, conn, appID, "OVER-0001")
	_ = pendingReqID

	activeReqID := insertApprovalRequest(t, ctx, conn, appID, "OVER-0002")
	activatedAt := time.Now()
	activeAuthID := insertAuthorization(t, ctx, conn, appID, activeReqID, authorizationOpts{ActivatedAt: &activatedAt, ExpiresAt: time.Now().Add(60 * 24 * time.Hour)})
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM authorizations WHERE id = $1`, activeAuthID) })

	expiringReqID := insertApprovalRequest(t, ctx, conn, appID, "OVER-0003")
	expiringAuthID := insertAuthorization(t, ctx, conn, appID, expiringReqID, authorizationOpts{ActivatedAt: &activatedAt, ExpiresAt: time.Now().Add(2 * 24 * time.Hour)})
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM authorizations WHERE id = $1`, expiringAuthID) })

	revokedReqID := insertApprovalRequest(t, ctx, conn, appID, "OVER-0004")
	revokedAt := time.Now()
	revokedAuthID := insertAuthorization(t, ctx, conn, appID, revokedReqID, authorizationOpts{ActivatedAt: &activatedAt, ExpiresAt: time.Now().Add(60 * 24 * time.Hour), RevokedAt: &revokedAt})
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM authorizations WHERE id = $1`, revokedAuthID) })

	counts, err := db.GetOverviewCounts(ctx, 7*24*time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("GetOverviewCounts: %v", err)
	}
	if counts.Pending < 1 {
		t.Errorf("Pending = %d, want at least 1", counts.Pending)
	}
	if counts.Active < 2 {
		t.Errorf("Active = %d, want at least 2 (the active and expiring-soon authorizations)", counts.Active)
	}
	if counts.ExpiringSoon < 1 {
		t.Errorf("ExpiringSoon = %d, want at least 1", counts.ExpiringSoon)
	}
	if counts.RevokedOrExpiredRecent < 1 {
		t.Errorf("RevokedOrExpiredRecent = %d, want at least 1", counts.RevokedOrExpiredRecent)
	}
}
