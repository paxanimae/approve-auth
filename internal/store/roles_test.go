package store_test

import (
	"context"
	"testing"
)

// TestRoles_AuditEventsInsertOnlyForRuntime exercises the audit-immutability
// design from migration 000012: the runtime role can INSERT audit_events
// but never UPDATE or DELETE them; only the maintenance role (used solely
// by retention jobs) can delete them (spec section 11, control 10).
func TestRoles_AuditEventsInsertOnlyForRuntime(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()

	runtime := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	maintenance := connectAs(t, ctx, dbURL, "approve_auth_maintenance", "devpassword")

	var eventID string
	err := runtime.QueryRow(ctx, `
		INSERT INTO audit_events (actor_type, action, correlation_id, outcome)
		VALUES ('system', 'test.roles.insert', gen_random_uuid(), 'success')
		RETURNING id`).Scan(&eventID)
	if err != nil {
		t.Fatalf("app_runtime INSERT into audit_events: expected success, got: %v", err)
	}

	_, err = runtime.Exec(ctx, `UPDATE audit_events SET reason = 'tampered' WHERE id = $1`, eventID)
	if err == nil {
		t.Fatal("app_runtime UPDATE on audit_events: expected permission denied, got nil error")
	}

	_, err = runtime.Exec(ctx, `DELETE FROM audit_events WHERE id = $1`, eventID)
	if err == nil {
		t.Fatal("app_runtime DELETE on audit_events: expected permission denied, got nil error")
	}

	// app_maintenance cannot read the table it doesn't own rows in? It can
	// -- it has SELECT + DELETE, which is exactly what retention needs.
	tag, err := maintenance.Exec(ctx, `DELETE FROM audit_events WHERE id = $1`, eventID)
	if err != nil {
		t.Fatalf("app_maintenance DELETE on audit_events: expected success, got: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("app_maintenance DELETE on audit_events: expected 1 row affected, got %d", tag.RowsAffected())
	}
}

func TestRoles_MaintenanceCannotInsertAuditEvents(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	maintenance := connectAs(t, ctx, dbURL, "approve_auth_maintenance", "devpassword")

	_, err := maintenance.Exec(ctx, `
		INSERT INTO audit_events (actor_type, action, correlation_id, outcome)
		VALUES ('system', 'test.roles.maintenance-insert', gen_random_uuid(), 'success')`)
	if err == nil {
		t.Fatal("app_maintenance INSERT into audit_events: expected permission denied, got nil error")
	}
}
