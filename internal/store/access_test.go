package store_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/frid-iks/approve-auth/internal/store"
)

func testTokenHash(seed string) []byte {
	h := sha256.Sum256([]byte(seed))
	return h[:]
}

func TestGetAccessSnapshot_UnknownHost(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	snap, err := db.GetAccessSnapshot(ctx, "unknown-host.example.test", testTokenHash(t.Name()))
	if err != nil {
		t.Fatalf("GetAccessSnapshot: %v", err)
	}
	if snap != nil {
		t.Errorf("expected nil snapshot for an unregistered hostname, got %+v", snap)
	}
}

func TestGetAccessSnapshot_KnownHostNoCredential(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "snapshot-no-cred.example.test")

	snap, err := db.GetAccessSnapshot(ctx, "snapshot-no-cred.example.test", testTokenHash(t.Name()))
	if err != nil {
		t.Fatalf("GetAccessSnapshot: %v", err)
	}
	if snap == nil {
		t.Fatal("expected a non-nil snapshot for a known host")
	}
	if snap.ApplicationID.String() != appID {
		t.Errorf("ApplicationID = %s, want %s", snap.ApplicationID, appID)
	}
	if snap.CredentialFound {
		t.Error("CredentialFound should be false when no credential matches the hash")
	}
}

func TestGetAccessSnapshot_ValidCredential(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "snapshot-valid.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, t.Name())
	activatedAt := time.Now().Add(-time.Hour)
	authID := insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),
		ActivatedAt: &activatedAt,
	})
	tokenHash := testTokenHash(t.Name())
	insertCredential(t, ctx, conn, authID, appID, tokenHash, credentialOpts{
		AbsoluteExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	})

	snap, err := db.GetAccessSnapshot(ctx, "snapshot-valid.example.test", tokenHash)
	if err != nil {
		t.Fatalf("GetAccessSnapshot: %v", err)
	}
	if snap == nil {
		t.Fatal("expected a non-nil snapshot")
	}
	if !snap.CredentialFound {
		t.Fatal("CredentialFound should be true")
	}
	if snap.CredentialApplicationID.String() != appID {
		t.Errorf("CredentialApplicationID = %s, want %s", snap.CredentialApplicationID, appID)
	}
	if snap.CredentialRevoked {
		t.Error("CredentialRevoked should be false")
	}
	if snap.AuthorizationRevoked {
		t.Error("AuthorizationRevoked should be false")
	}
	if !snap.AuthorizationActivated {
		t.Error("AuthorizationActivated should be true")
	}
	if !snap.DatabaseNow.Before(snap.AuthorizationExpiresAt) {
		t.Errorf("DatabaseNow (%s) should be before AuthorizationExpiresAt (%s)", snap.DatabaseNow, snap.AuthorizationExpiresAt)
	}
	if !snap.DatabaseNow.Before(snap.CredentialAbsoluteExpiresAt) {
		t.Errorf("DatabaseNow (%s) should be before CredentialAbsoluteExpiresAt (%s)", snap.DatabaseNow, snap.CredentialAbsoluteExpiresAt)
	}
}

func TestGetAccessSnapshot_CredentialForDifferentApplication(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appA := insertApplication(t, ctx, conn, "snapshot-app-a.example.test")
	appB := insertApplication(t, ctx, conn, "snapshot-app-b.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appA, t.Name())
	activatedAt := time.Now().Add(-time.Hour)
	authID := insertAuthorization(t, ctx, conn, appA, reqID, authorizationOpts{
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),
		ActivatedAt: &activatedAt,
	})
	tokenHash := testTokenHash(t.Name())
	insertCredential(t, ctx, conn, authID, appA, tokenHash, credentialOpts{
		AbsoluteExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	})

	// The credential is valid for app A, but we ask about app B's hostname.
	snap, err := db.GetAccessSnapshot(ctx, "snapshot-app-b.example.test", tokenHash)
	if err != nil {
		t.Fatalf("GetAccessSnapshot: %v", err)
	}
	if snap == nil {
		t.Fatal("expected a non-nil snapshot (app B is registered)")
	}
	if snap.CredentialFound {
		// The credential exists in the DB, but not scoped to app B's hostname --
		// the join only matches token_hash, so CredentialFound reflects a raw hash
		// match. The caller (authz) must additionally compare CredentialApplicationID
		// against ApplicationID and deny on mismatch; assert that mismatch is visible here.
		if snap.CredentialApplicationID.String() == appB {
			t.Fatal("credential's application_id should be app A, not app B")
		}
		if snap.CredentialApplicationID.String() != appA {
			t.Errorf("CredentialApplicationID = %s, want %s (app A)", snap.CredentialApplicationID, appA)
		}
	} else {
		t.Fatal("CredentialFound should be true (the hash exists) -- the mismatch is in CredentialApplicationID vs ApplicationID")
	}
}

func TestGetAccessSnapshot_IncludesLastSeenAndRevokePolicyOverrides(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "snapshot-policy.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, t.Name())
	activatedAt := time.Now().Add(-time.Hour)
	authID := insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),
		ActivatedAt: &activatedAt,
	})
	tokenHash := testTokenHash(t.Name())
	insertCredential(t, ctx, conn, authID, appID, tokenHash, credentialOpts{
		AbsoluteExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	})

	if _, err := conn.Exec(ctx, `UPDATE applications SET revoke_policy_ip_changed = 'flag_for_review' WHERE id = $1`, appID); err != nil {
		t.Fatalf("setting application override: %v", err)
	}
	if _, err := conn.Exec(ctx, `
		UPDATE authorizations
		SET last_seen_ip = '203.0.113.9', last_seen_user_agent = 'old-agent/1.0', revoke_policy_user_agent_changed = 'revoke'
		WHERE id = $1`, authID); err != nil {
		t.Fatalf("setting session state/override: %v", err)
	}

	snap, err := db.GetAccessSnapshot(ctx, "snapshot-policy.example.test", tokenHash)
	if err != nil {
		t.Fatalf("GetAccessSnapshot: %v", err)
	}
	if snap == nil {
		t.Fatal("expected a non-nil snapshot")
	}
	if snap.AuthorizationVersion == 0 {
		t.Error("AuthorizationVersion should be populated (starts at 1)")
	}
	if snap.LastSeenIP == nil || snap.LastSeenIP.String() != "203.0.113.9" {
		t.Errorf("LastSeenIP = %v, want 203.0.113.9", snap.LastSeenIP)
	}
	if snap.LastSeenUserAgent == nil || *snap.LastSeenUserAgent != "old-agent/1.0" {
		t.Errorf("LastSeenUserAgent = %v, want old-agent/1.0", snap.LastSeenUserAgent)
	}
	if snap.RevokePolicyIPChangedApp == nil || *snap.RevokePolicyIPChangedApp != "flag_for_review" {
		t.Errorf("RevokePolicyIPChangedApp = %v, want flag_for_review", snap.RevokePolicyIPChangedApp)
	}
	if snap.RevokePolicyIPChangedSession != nil {
		t.Errorf("RevokePolicyIPChangedSession = %v, want nil (no session override was set)", snap.RevokePolicyIPChangedSession)
	}
	if snap.RevokePolicyUserAgentChangedSession == nil || *snap.RevokePolicyUserAgentChangedSession != "revoke" {
		t.Errorf("RevokePolicyUserAgentChangedSession = %v, want revoke", snap.RevokePolicyUserAgentChangedSession)
	}
}

// TestGetAccessSnapshot_ReflectsLiveGlobalSettingsChange is this
// session's settings overhaul's actual point: global_settings
// (migration 000019) is read fresh by GetAccessSnapshot's own query on
// every call, never cached in a startup-loaded Config, so an
// administrator's edit via the Settings page takes effect on the very
// next authz.Decide call with no restart.
func TestGetAccessSnapshot_ReflectsLiveGlobalSettingsChange(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	withGlobalSettingsRestore(t, db, ctx)

	appID := insertApplication(t, ctx, conn, "snapshot-global-settings.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, t.Name())
	activatedAt := time.Now().Add(-time.Hour)
	authID := insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),
		ActivatedAt: &activatedAt,
	})
	tokenHash := testTokenHash(t.Name())
	insertCredential(t, ctx, conn, authID, appID, tokenHash, credentialOpts{
		AbsoluteExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	})

	original, err := db.GetGlobalSettings(ctx)
	if err != nil {
		t.Fatalf("GetGlobalSettings: %v", err)
	}
	ipAction, uaAction := "revoke", "flag_for_review"
	if _, err := db.UpdateGlobalSettings(ctx, original.Version, store.UpdateGlobalSettingsParams{
		RevokePolicyIPChanged: &ipAction, RevokePolicyUserAgentChanged: &uaAction,
	}, "test"); err != nil {
		t.Fatalf("UpdateGlobalSettings: %v", err)
	}

	snap, err := db.GetAccessSnapshot(ctx, "snapshot-global-settings.example.test", tokenHash)
	if err != nil {
		t.Fatalf("GetAccessSnapshot: %v", err)
	}
	if snap == nil {
		t.Fatal("expected a non-nil snapshot")
	}
	if snap.RevokePolicyIPChangedGlobal != "revoke" {
		t.Errorf("RevokePolicyIPChangedGlobal = %q, want revoke (the value just written via UpdateGlobalSettings)", snap.RevokePolicyIPChangedGlobal)
	}
	if snap.RevokePolicyUserAgentChangedGlobal != "flag_for_review" {
		t.Errorf("RevokePolicyUserAgentChangedGlobal = %q, want flag_for_review (the value just written via UpdateGlobalSettings)", snap.RevokePolicyUserAgentChangedGlobal)
	}
}

func TestTouchLastSeen_CoalescesWithinOneMinute(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "last-seen.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, t.Name())
	authIDStr := insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	})

	if err := db.TouchLastSeen(ctx, mustParseUUID(t, authIDStr), "203.0.113.5", "test-agent/1.0"); err != nil {
		t.Fatalf("TouchLastSeen (first call): %v", err)
	}

	var firstSeenAt time.Time
	if err := conn.QueryRow(ctx, `SELECT last_seen_at FROM authorizations WHERE id = $1`, authIDStr).Scan(&firstSeenAt); err != nil {
		t.Fatalf("querying last_seen_at: %v", err)
	}
	if firstSeenAt.IsZero() {
		t.Fatal("expected last_seen_at to be set after the first TouchLastSeen call")
	}

	// A second call within the same minute must be a no-op (coalesced).
	if err := db.TouchLastSeen(ctx, mustParseUUID(t, authIDStr), "203.0.113.5", "test-agent/1.0"); err != nil {
		t.Fatalf("TouchLastSeen (second call): %v", err)
	}
	var secondSeenAt time.Time
	if err := conn.QueryRow(ctx, `SELECT last_seen_at FROM authorizations WHERE id = $1`, authIDStr).Scan(&secondSeenAt); err != nil {
		t.Fatalf("querying last_seen_at: %v", err)
	}
	if !secondSeenAt.Equal(firstSeenAt) {
		t.Errorf("last_seen_at changed on a coalesced call: %s -> %s", firstSeenAt, secondSeenAt)
	}
}
