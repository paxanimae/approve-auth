package audit_test

import (
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/frid-iks/approve-auth/internal/audit"
	"github.com/frid-iks/approve-auth/internal/store"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}

	if err := store.MigrateUp(base); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}

	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parsing TEST_DATABASE_URL: %v", err)
	}
	u.User = url.UserPassword("approve_auth_app", "devpassword")

	pool, err := pgxpool.New(context.Background(), u.String())
	if err != nil {
		t.Fatalf("connecting as approve_auth_app: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// testMaintenancePool cleans up rows the app_runtime pool cannot delete
// itself (audit_events is insert-only for that role by design).
func testMaintenancePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parsing TEST_DATABASE_URL: %v", err)
	}
	u.User = url.UserPassword("approve_auth_maintenance", "devpassword")

	pool, err := pgxpool.New(context.Background(), u.String())
	if err != nil {
		t.Fatalf("connecting as approve_auth_maintenance: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestPostgresLogger_RecordsAndIsInsertOnly(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	logger := audit.NewPostgresLogger(pool)

	correlationID := uuid.New()
	err := logger.Record(ctx, audit.Event{
		ActorType:     "system",
		Action:        "test.audit.record",
		CorrelationID: correlationID,
		Outcome:       "success",
	})
	if err != nil {
		t.Fatalf("Record: expected success, got: %v", err)
	}

	var id string
	err = pool.QueryRow(ctx, `SELECT id FROM audit_events WHERE correlation_id = $1`, correlationID).Scan(&id)
	if err != nil {
		t.Fatalf("querying back the recorded event: %v", err)
	}
	maintenance := testMaintenancePool(t)
	t.Cleanup(func() {
		_, _ = maintenance.Exec(ctx, `DELETE FROM audit_events WHERE id = $1`, id)
	})

	// The audit package exposes no method that could do this -- this proves
	// the underlying database grant (not just API surface) is what blocks
	// it, exercised through the same pool the real Logger uses.
	_, err = pool.Exec(ctx, `UPDATE audit_events SET reason = 'tampered' WHERE id = $1`, id)
	if err == nil {
		t.Fatal("UPDATE audit_events via the app_runtime pool: expected permission denied, got nil error")
	}
}

func TestPostgresLogger_RecordsWithOptionalFieldsNil(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	logger := audit.NewPostgresLogger(pool)

	correlationID := uuid.New()
	err := logger.Record(ctx, audit.Event{
		ActorType:     "browser",
		Action:        "test.audit.record-minimal",
		CorrelationID: correlationID,
		Outcome:       "failure",
	})
	if err != nil {
		t.Fatalf("Record with all optional fields nil: expected success, got: %v", err)
	}

	maintenance := testMaintenancePool(t)
	t.Cleanup(func() {
		_, _ = maintenance.Exec(ctx, `DELETE FROM audit_events WHERE correlation_id = $1`, correlationID)
	})
}
