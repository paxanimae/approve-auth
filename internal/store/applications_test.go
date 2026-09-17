package store_test

import (
	"context"
	"testing"
	"time"
)

func TestCreateAndGetApplication(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	created, err := db.CreateApplication(ctx, "Repo-Test.example.test", "Repo Test App", "created by applications_test.go", 30*24*time.Hour, 365*24*time.Hour)
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
	db := openStoreAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	_, ok, err := db.GetApplicationByHostname(ctx, "does-not-exist.example.test")
	if err != nil {
		t.Fatalf("GetApplicationByHostname: %v", err)
	}
	if ok {
		t.Error("expected not-found for an unregistered hostname")
	}
}
