package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestGrantApplicationOwner_GrantsAndListsAndIsIdempotent covers the
// ApplicationOwner role's data-model foundation: granting is visible
// both from the application's side (ListApplicationOwners) and the
// subject's side (GetOwnedApplicationIDs), and granting the same pair
// twice is a no-op, not a duplicate-key error (spec: idempotent so a
// re-run of a provisioning script never fails).
func TestGrantApplicationOwner_GrantsAndListsAndIsIdempotent(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appIDStr := insertApplication(t, ctx, conn, "grant-owner.example.test")
	appID := uuid.MustParse(appIDStr)

	if err := db.GrantApplicationOwner(ctx, appID, "owner-a", "admin-1"); err != nil {
		t.Fatalf("GrantApplicationOwner: %v", err)
	}
	// Granting the same pair again must not error.
	if err := db.GrantApplicationOwner(ctx, appID, "owner-a", "admin-1"); err != nil {
		t.Fatalf("GrantApplicationOwner (repeat): %v", err)
	}

	owners, err := db.ListApplicationOwners(ctx, appID)
	if err != nil {
		t.Fatalf("ListApplicationOwners: %v", err)
	}
	if len(owners) != 1 || owners[0] != "owner-a" {
		t.Errorf("ListApplicationOwners = %+v, want exactly [owner-a]", owners)
	}

	owned, err := db.GetOwnedApplicationIDs(ctx, "owner-a")
	if err != nil {
		t.Fatalf("GetOwnedApplicationIDs: %v", err)
	}
	found := false
	for _, id := range owned {
		if id == appID {
			found = true
		}
	}
	if !found {
		t.Errorf("GetOwnedApplicationIDs(owner-a) = %+v, want to include %s", owned, appID)
	}
}

// TestRevokeApplicationOwner_RemovesGrantAndIsIdempotent is
// GrantApplicationOwner's inverse: revoking removes the grant from both
// views, and revoking a subject who was never granted ownership (or
// already revoked) is a no-op, not an error.
func TestRevokeApplicationOwner_RemovesGrantAndIsIdempotent(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appIDStr := insertApplication(t, ctx, conn, "revoke-owner.example.test")
	appID := uuid.MustParse(appIDStr)

	if err := db.GrantApplicationOwner(ctx, appID, "owner-b", "admin-1"); err != nil {
		t.Fatalf("GrantApplicationOwner: %v", err)
	}
	if err := db.RevokeApplicationOwner(ctx, appID, "owner-b", "admin-1"); err != nil {
		t.Fatalf("RevokeApplicationOwner: %v", err)
	}
	// Revoking again (already revoked) must not error.
	if err := db.RevokeApplicationOwner(ctx, appID, "owner-b", "admin-1"); err != nil {
		t.Fatalf("RevokeApplicationOwner (repeat): %v", err)
	}
	// Revoking a subject who was never granted ownership must not error.
	if err := db.RevokeApplicationOwner(ctx, appID, "never-owned", "admin-1"); err != nil {
		t.Fatalf("RevokeApplicationOwner (never owned): %v", err)
	}

	owners, err := db.ListApplicationOwners(ctx, appID)
	if err != nil {
		t.Fatalf("ListApplicationOwners: %v", err)
	}
	if len(owners) != 0 {
		t.Errorf("ListApplicationOwners after revoke = %+v, want empty", owners)
	}

	owned, err := db.GetOwnedApplicationIDs(ctx, "owner-b")
	if err != nil {
		t.Fatalf("GetOwnedApplicationIDs: %v", err)
	}
	for _, id := range owned {
		if id == appID {
			t.Errorf("GetOwnedApplicationIDs(owner-b) still includes %s after revoke", appID)
		}
	}
}

// TestGrantApplicationOwner_UnknownApplicationFails proves the FK to
// applications is enforced -- internal/admin.Service relies on this
// constraint violation (via pgConstraintName) to map to ErrNotFound.
func TestGrantApplicationOwner_UnknownApplicationFails(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	if err := db.GrantApplicationOwner(ctx, uuid.New(), "owner-c", "admin-1"); err == nil {
		t.Error("GrantApplicationOwner with an unknown application id: got nil error, want a foreign-key violation")
	}
}
