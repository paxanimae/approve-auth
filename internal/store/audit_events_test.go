package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/frid-iks/approve-auth/internal/store"
)

func TestListAuditEvents_FiltersByApplicationAndAction(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	app, err := db.CreateApplication(ctx, "audit-list.example.test", "Audit List App", "", 30*24*time.Hour, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, app.ID) })
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM audit_events WHERE application_id = $1`, app.ID) })

	// CreateApplication itself already wrote one "application.created" event.
	events, err := db.ListAuditEvents(ctx, store.ListAuditEventsParams{ApplicationID: &app.ID})
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("ListAuditEvents: got %d events, want 1", len(events))
	}
	if events[0].Action != "application.created" {
		t.Errorf("Action = %q, want application.created", events[0].Action)
	}

	newName := "Renamed"
	if _, err := db.UpdateApplication(ctx, app.ID, app.Version, store.UpdateApplicationParams{DisplayName: &newName}, "admin@example.test"); err != nil {
		t.Fatalf("UpdateApplication: %v", err)
	}

	events, err = db.ListAuditEvents(ctx, store.ListAuditEventsParams{ApplicationID: &app.ID, Action: "application.updated"})
	if err != nil {
		t.Fatalf("ListAuditEvents (filtered by action): %v", err)
	}
	if len(events) != 1 || events[0].Action != "application.updated" {
		t.Fatalf("ListAuditEvents (filtered by action): got %+v, want exactly one application.updated event", events)
	}

	unfiltered, err := db.ListAuditEvents(ctx, store.ListAuditEventsParams{ApplicationID: &app.ID})
	if err != nil {
		t.Fatalf("ListAuditEvents (unfiltered): %v", err)
	}
	if len(unfiltered) != 2 {
		t.Fatalf("ListAuditEvents (unfiltered): got %d events, want 2 (created + updated)", len(unfiltered))
	}
	// Newest first.
	if unfiltered[0].Action != "application.updated" || unfiltered[1].Action != "application.created" {
		t.Errorf("ListAuditEvents ordering: got [%s, %s], want [application.updated, application.created]", unfiltered[0].Action, unfiltered[1].Action)
	}
}
