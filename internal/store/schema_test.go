package store_test

import (
	"context"
	"testing"

	"github.com/frid-iks/traefik-manual-proxy/internal/store"
)

func TestSchemaReady(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	ready, err := db.SchemaReady(ctx)
	if err != nil {
		t.Fatalf("SchemaReady: %v", err)
	}
	if !ready {
		t.Error("SchemaReady() = false after TestMain's migrate up; want true")
	}
}

func TestSchemaReady_FalseAfterMigrateDown(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()

	if err := store.MigrateDown(dbURL); err != nil {
		t.Fatalf("MigrateDown: %v", err)
	}
	t.Cleanup(func() {
		if err := store.MigrateUp(dbURL); err != nil {
			t.Fatalf("MigrateUp (restoring schema for later tests): %v", err)
		}
	})

	db := openStoreAs(t, ctx, dbURL, "postgres", "devpassword")
	ready, err := db.SchemaReady(ctx)
	if err != nil {
		t.Fatalf("SchemaReady: %v", err)
	}
	if ready {
		t.Error("SchemaReady() = true right after MigrateDown; want false")
	}
}
