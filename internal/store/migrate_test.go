package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/frid-iks/traefik-manual-proxy/internal/store"
)

func TestMigrate_UpDownRoundTrip(t *testing.T) {
	dbURL := skipIfNoDB(t)

	if err := store.MigrateDown(dbURL); err != nil {
		t.Fatalf("MigrateDown: %v", err)
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	var exists bool
	err = conn.QueryRow(ctx, `SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'applications')`).Scan(&exists)
	if err != nil {
		t.Fatalf("checking applications table: %v", err)
	}
	if exists {
		t.Fatal("applications table still exists after MigrateDown")
	}

	if err := store.MigrateUp(dbURL); err != nil {
		t.Fatalf("MigrateUp (after down): %v", err)
	}

	err = conn.QueryRow(ctx, `SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'applications')`).Scan(&exists)
	if err != nil {
		t.Fatalf("checking applications table: %v", err)
	}
	if !exists {
		t.Fatal("applications table missing after MigrateUp")
	}

	// MigrateUp must be idempotent (no pending changes -> no error).
	if err := store.MigrateUp(dbURL); err != nil {
		t.Fatalf("MigrateUp (idempotent re-run): %v", err)
	}
}
