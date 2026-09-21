package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/paxanimae/approve-auth/internal/admin"
)

func TestGrantApplicationOwner_Success(t *testing.T) {
	db, svc := openService(t)
	ctx := context.Background()

	app, err := svc.CreateApplication(ctx, admin.CreateApplicationInput{
		Hostname: "admin-grant-owner-" + randomSuffix(t) + ".example.test", DisplayName: "Grant Owner Test",
	})
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	cleanupApplication(t, db, ctx, app.ID)

	if err := svc.GrantApplicationOwner(ctx, admin.GrantApplicationOwnerInput{
		ApplicationID: app.ID.String(), Subject: "owner-1", GrantedBy: "admin-1",
	}); err != nil {
		t.Fatalf("GrantApplicationOwner: %v", err)
	}

	owners, err := db.ListApplicationOwners(ctx, app.ID)
	if err != nil {
		t.Fatalf("ListApplicationOwners: %v", err)
	}
	if len(owners) != 1 || owners[0] != "owner-1" {
		t.Errorf("ListApplicationOwners = %+v, want exactly [owner-1]", owners)
	}
}

func TestGrantApplicationOwner_UnknownApplicationReturnsErrNotFound(t *testing.T) {
	_, svc := openService(t)
	ctx := context.Background()

	err := svc.GrantApplicationOwner(ctx, admin.GrantApplicationOwnerInput{
		ApplicationID: "00000000-0000-0000-0000-000000000000", Subject: "owner-1", GrantedBy: "admin-1",
	})
	if !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("GrantApplicationOwner(unknown application) = %v, want ErrNotFound", err)
	}
}

func TestRevokeApplicationOwner_Success(t *testing.T) {
	db, svc := openService(t)
	ctx := context.Background()

	app, err := svc.CreateApplication(ctx, admin.CreateApplicationInput{
		Hostname: "admin-revoke-owner-" + randomSuffix(t) + ".example.test", DisplayName: "Revoke Owner Test",
	})
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	cleanupApplication(t, db, ctx, app.ID)

	if err := svc.GrantApplicationOwner(ctx, admin.GrantApplicationOwnerInput{
		ApplicationID: app.ID.String(), Subject: "owner-1", GrantedBy: "admin-1",
	}); err != nil {
		t.Fatalf("GrantApplicationOwner: %v", err)
	}
	if err := svc.RevokeApplicationOwner(ctx, admin.RevokeApplicationOwnerInput{
		ApplicationID: app.ID.String(), Subject: "owner-1", RevokedBy: "admin-1",
	}); err != nil {
		t.Fatalf("RevokeApplicationOwner: %v", err)
	}

	owners, err := db.ListApplicationOwners(ctx, app.ID)
	if err != nil {
		t.Fatalf("ListApplicationOwners: %v", err)
	}
	if len(owners) != 0 {
		t.Errorf("ListApplicationOwners after revoke = %+v, want empty", owners)
	}
}
