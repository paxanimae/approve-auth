package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/store"
)

func TestCreateAndGetApplication(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	created, err := db.CreateApplication(ctx, "Repo-Test.example.test", "Repo Test App", "created by applications_test.go", 30*24*time.Hour, 365*24*time.Hour, "", "", "")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, created.ID) })

	if created.Hostname != "repo-test.example.test" {
		t.Errorf("Hostname = %q, want lowercased", created.Hostname)
	}
	if !created.Enabled {
		t.Error("newly created application should default to enabled")
	}

	found, ok, err := db.GetApplicationByHostname(ctx, "REPO-TEST.example.test")
	if err != nil {
		t.Fatalf("GetApplicationByHostname: %v", err)
	}
	if !ok {
		t.Fatal("GetApplicationByHostname: got not-found for a hostname that was just created (case-insensitive lookup expected)")
	}
	if found.ID != created.ID {
		t.Errorf("GetApplicationByHostname returned a different application: got %s, want %s", found.ID, created.ID)
	}
}

func TestGetApplicationByHostname_NotFound(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	_, ok, err := db.GetApplicationByHostname(ctx, "does-not-exist.example.test")
	if err != nil {
		t.Fatalf("GetApplicationByHostname: %v", err)
	}
	if ok {
		t.Error("expected not-found for an unregistered hostname")
	}
}

func TestGetApplicationByID(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	created, err := db.CreateApplication(ctx, "by-id.example.test", "By ID App", "", 30*24*time.Hour, 365*24*time.Hour, "", "", "")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, created.ID) })

	found, ok, err := db.GetApplicationByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetApplicationByID: %v", err)
	}
	if !ok || found.ID != created.ID {
		t.Fatalf("GetApplicationByID: got (%+v, %v), want the created application", found, ok)
	}

	_, ok, err = db.GetApplicationByID(ctx, uuid.New())
	if err != nil {
		t.Fatalf("GetApplicationByID (random id): %v", err)
	}
	if ok {
		t.Error("expected not-found for a random id")
	}
}

func TestListApplications(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	a, err := db.CreateApplication(ctx, "list-a.example.test", "List A", "", 30*24*time.Hour, 365*24*time.Hour, "", "", "")
	if err != nil {
		t.Fatalf("CreateApplication a: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, a.ID) })
	b, err := db.CreateApplication(ctx, "list-b.example.test", "List B", "", 30*24*time.Hour, 365*24*time.Hour, "", "", "")
	if err != nil {
		t.Fatalf("CreateApplication b: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, b.ID) })

	apps, err := db.ListApplications(ctx)
	if err != nil {
		t.Fatalf("ListApplications: %v", err)
	}
	var sawA, sawB bool
	for _, app := range apps {
		if app.ID == a.ID {
			sawA = true
		}
		if app.ID == b.ID {
			sawB = true
		}
	}
	if !sawA || !sawB {
		t.Errorf("ListApplications: missing seeded applications (sawA=%v, sawB=%v)", sawA, sawB)
	}
}

func TestUpdateApplication_AppliesPartialChangesAndDetectsConflict(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	created, err := db.CreateApplication(ctx, "update.example.test", "Original Name", "original description", 30*24*time.Hour, 365*24*time.Hour, "", "", "")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, created.ID) })

	newName := "New Name"
	updated, err := db.UpdateApplication(ctx, created.ID, created.Version, store.UpdateApplicationParams{DisplayName: &newName}, "admin@example.test")
	if err != nil {
		t.Fatalf("UpdateApplication: %v", err)
	}
	if updated.DisplayName != "New Name" {
		t.Errorf("DisplayName = %q, want New Name", updated.DisplayName)
	}
	if updated.Description != "original description" {
		t.Errorf("Description = %q, want unchanged original description", updated.Description)
	}
	if updated.Version != created.Version+1 {
		t.Errorf("Version = %d, want %d", updated.Version, created.Version+1)
	}

	// Reusing the now-stale original version must conflict.
	_, err = db.UpdateApplication(ctx, created.ID, created.Version, store.UpdateApplicationParams{DisplayName: &newName}, "admin@example.test")
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("UpdateApplication with stale version: got %v, want ErrConflict", err)
	}
}

func TestDisableApplication_CancelsPendingAndRevokesLiveAuthorizations(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "postgres", "devpassword")

	appID := insertApplication(t, ctx, conn, "disable.example.test")
	pendingRequestID := insertApprovalRequest(t, ctx, conn, appID, "AAAA-1111")
	claimedRequestID := insertApprovalRequest(t, ctx, conn, appID, "BBBB-2222")
	// Already claimed -- its request is terminal (not pending/approved), so
	// DisableApplication must not touch its status, only revoke the
	// authorization it produced.
	if _, err := conn.Exec(ctx, `UPDATE approval_requests SET status = 'claimed', claimed_at = now() WHERE id = $1`, claimedRequestID); err != nil {
		t.Fatalf("marking request claimed: %v", err)
	}
	now := time.Now()
	liveAuthID := insertAuthorization(t, ctx, conn, appID, claimedRequestID, authorizationOpts{ExpiresAt: time.Now().Add(24 * time.Hour), ActivatedAt: &now})
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM authorizations WHERE id = $1`, liveAuthID) })

	appUUID := mustParseUUID(t, appID)
	updated, canceled, revoked, err := db.DisableApplication(ctx, appUUID, 1, "compromised device", "admin@example.test")
	if err != nil {
		t.Fatalf("DisableApplication: %v", err)
	}
	if updated.Enabled {
		t.Error("application should be disabled")
	}
	if canceled != 1 {
		t.Errorf("canceledRequests = %d, want 1 (only the pending one)", canceled)
	}
	if revoked != 1 {
		t.Errorf("revokedAuthorizations = %d, want 1", revoked)
	}

	var status string
	if err := conn.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id = $1`, pendingRequestID).Scan(&status); err != nil {
		t.Fatalf("checking pending request status: %v", err)
	}
	if status != "canceled" {
		t.Errorf("pending request status = %q, want canceled", status)
	}

	var revokedAt *time.Time
	if err := conn.QueryRow(ctx, `SELECT revoked_at FROM authorizations WHERE id = $1`, liveAuthID).Scan(&revokedAt); err != nil {
		t.Fatalf("checking authorization revoked_at: %v", err)
	}
	if revokedAt == nil {
		t.Error("authorization should be revoked")
	}

	// Stale version now conflicts.
	_, _, _, err = db.DisableApplication(ctx, appUUID, 1, "again", "admin@example.test")
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("DisableApplication with stale version: got %v, want ErrConflict", err)
	}
}

func TestEnableApplication(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	created, err := db.CreateApplication(ctx, "enable.example.test", "Enable Test", "", 30*24*time.Hour, 365*24*time.Hour, "", "", "")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, created.ID) })

	disabled, _, _, err := db.DisableApplication(ctx, created.ID, created.Version, "test", "admin@example.test")
	if err != nil {
		t.Fatalf("DisableApplication: %v", err)
	}

	enabled, err := db.EnableApplication(ctx, created.ID, disabled.Version, "admin@example.test")
	if err != nil {
		t.Fatalf("EnableApplication: %v", err)
	}
	if !enabled.Enabled {
		t.Error("application should be enabled again")
	}
}

func TestApplication_ContactInfo(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	withOverride, err := db.CreateApplication(ctx, "contact-override.example.test", "Has Override", "", 30*24*time.Hour, 365*24*time.Hour, "call +1-555-0100", "", "")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, withOverride.ID) })
	if withOverride.ContactInfo == nil || *withOverride.ContactInfo != "call +1-555-0100" {
		t.Errorf("ContactInfo = %v, want \"call +1-555-0100\"", withOverride.ContactInfo)
	}

	noOverride, err := db.CreateApplication(ctx, "contact-default.example.test", "No Override", "", 30*24*time.Hour, 365*24*time.Hour, "", "", "")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, noOverride.ID) })
	if noOverride.ContactInfo != nil {
		t.Errorf("ContactInfo = %v, want nil (inherits the global default)", *noOverride.ContactInfo)
	}

	newValue := "email ops@example.test"
	updated, err := db.UpdateApplication(ctx, noOverride.ID, noOverride.Version, store.UpdateApplicationParams{ContactInfo: &newValue}, "admin@example.test")
	if err != nil {
		t.Fatalf("UpdateApplication (set): %v", err)
	}
	if updated.ContactInfo == nil || *updated.ContactInfo != newValue {
		t.Errorf("ContactInfo after setting = %v, want %q", updated.ContactInfo, newValue)
	}

	cleared := ""
	recleared, err := db.UpdateApplication(ctx, updated.ID, updated.Version, store.UpdateApplicationParams{ContactInfo: &cleared}, "admin@example.test")
	if err != nil {
		t.Fatalf("UpdateApplication (clear): %v", err)
	}
	if recleared.ContactInfo != nil {
		t.Errorf("ContactInfo after clearing with \"\" = %v, want nil", *recleared.ContactInfo)
	}
}
