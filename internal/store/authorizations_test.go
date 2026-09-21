package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestListAuthorizations_FiltersByApprovedBy covers "My Approvals":
// approvedBy narrows the listing to sessions a specific admin approved,
// matched against the same stable value every audit actor field uses.
func TestListAuthorizations_FiltersByApprovedBy(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "list-authz-filter.example.test")
	reqA := insertApprovalRequest(t, ctx, conn, appID, "code-a")
	reqB := insertApprovalRequest(t, ctx, conn, appID, "code-b")
	authA := insertAuthorization(t, ctx, conn, appID, reqA, authorizationOpts{ExpiresAt: time.Now().Add(time.Hour)})
	authB := insertAuthorization(t, ctx, conn, appID, reqB, authorizationOpts{ExpiresAt: time.Now().Add(time.Hour)})
	if _, err := conn.Exec(ctx, `UPDATE authorizations SET approved_by = 'admin-a' WHERE id = $1`, authA); err != nil {
		t.Fatalf("setting approved_by for authA: %v", err)
	}
	if _, err := conn.Exec(ctx, `UPDATE authorizations SET approved_by = 'admin-b' WHERE id = $1`, authB); err != nil {
		t.Fatalf("setting approved_by for authB: %v", err)
	}

	adminA := "admin-a"
	mine, err := db.ListAuthorizations(ctx, nil, &adminA, false, 100, nil)
	if err != nil {
		t.Fatalf("ListAuthorizations(approvedBy=admin-a): %v", err)
	}
	if len(mine) != 1 || mine[0].ID.String() != authA {
		t.Errorf("ListAuthorizations(approvedBy=admin-a) = %+v, want exactly authA", mine)
	}

	all, err := db.ListAuthorizations(ctx, nil, nil, false, 100, nil)
	if err != nil {
		t.Fatalf("ListAuthorizations(approvedBy=nil): %v", err)
	}
	found := 0
	for _, a := range all {
		if a.ID.String() == authA || a.ID.String() == authB {
			found++
		}
	}
	if found != 2 {
		t.Errorf("ListAuthorizations(approvedBy=nil) should include both authA and authB, found %d of 2", found)
	}
}

// TestListAuthorizations_RestrictToApplicationIDs covers the
// ApplicationOwner scoping path: a non-nil restrictToApplicationIDs
// narrows the listing to only those applications, same as
// ListApprovalRequests' own restriction.
func TestListAuthorizations_RestrictToApplicationIDs(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appA := insertApplication(t, ctx, conn, "list-authz-restrict-a.example.test")
	appB := insertApplication(t, ctx, conn, "list-authz-restrict-b.example.test")
	reqA := insertApprovalRequest(t, ctx, conn, appA, "restrict-code-a")
	reqB := insertApprovalRequest(t, ctx, conn, appB, "restrict-code-b")
	authA := insertAuthorization(t, ctx, conn, appA, reqA, authorizationOpts{ExpiresAt: time.Now().Add(time.Hour)})
	authB := insertAuthorization(t, ctx, conn, appB, reqB, authorizationOpts{ExpiresAt: time.Now().Add(time.Hour)})

	restricted, err := db.ListAuthorizations(ctx, nil, nil, false, 100, []uuid.UUID{uuid.MustParse(appA)})
	if err != nil {
		t.Fatalf("ListAuthorizations(restrict=appA): %v", err)
	}
	for _, a := range restricted {
		if a.ID.String() == authB {
			t.Errorf("ListAuthorizations(restrict=appA) unexpectedly included authB from appB")
		}
	}
	foundA := false
	for _, a := range restricted {
		if a.ID.String() == authA {
			foundA = true
		}
	}
	if !foundA {
		t.Errorf("ListAuthorizations(restrict=appA) should include authA")
	}
}
