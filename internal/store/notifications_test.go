package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNotificationOutbox_EnqueueListMarkDeliveredFailedAndPurge(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "notify-outbox.example.test")
	appUUID := uuid.MustParse(appID)

	if err := db.EnqueueNotification(ctx, appUUID, "request.created", []byte(`{"request_id":"r-1"}`)); err != nil {
		t.Fatalf("EnqueueNotification: %v", err)
	}

	pending, err := db.ListPendingNotifications(ctx, 100)
	if err != nil {
		t.Fatalf("ListPendingNotifications: %v", err)
	}
	var found bool
	var itemID uuid.UUID
	for _, p := range pending {
		if p.ApplicationID == appUUID && p.EventType == "request.created" {
			found, itemID = true, p.ID
			var decoded struct {
				RequestID string `json:"request_id"`
			}
			if err := json.Unmarshal(p.Payload, &decoded); err != nil {
				t.Errorf("unmarshaling payload %s: %v", p.Payload, err)
			} else if decoded.RequestID != "r-1" {
				t.Errorf("Payload request_id = %q, want r-1", decoded.RequestID)
			}
			if p.Attempts != 0 {
				t.Errorf("Attempts = %d, want 0 for a fresh row", p.Attempts)
			}
		}
	}
	if !found {
		t.Fatal("enqueued notification did not appear in ListPendingNotifications")
	}

	// A failed attempt bumps attempts and pushes next_attempt_at into
	// the future, so it must drop out of the pending set immediately.
	if err := db.MarkNotificationFailed(ctx, itemID, time.Now().Add(time.Hour), "connection refused"); err != nil {
		t.Fatalf("MarkNotificationFailed: %v", err)
	}
	pendingAfterFailure, err := db.ListPendingNotifications(ctx, 100)
	if err != nil {
		t.Fatalf("ListPendingNotifications (after failure): %v", err)
	}
	for _, p := range pendingAfterFailure {
		if p.ID == itemID {
			t.Error("failed notification with a future next_attempt_at still appeared as pending")
		}
	}

	if err := db.MarkNotificationDelivered(ctx, itemID); err != nil {
		t.Fatalf("MarkNotificationDelivered: %v", err)
	}
	pendingAfterDelivery, err := db.ListPendingNotifications(ctx, 100)
	if err != nil {
		t.Fatalf("ListPendingNotifications (after delivery): %v", err)
	}
	for _, p := range pendingAfterDelivery {
		if p.ID == itemID {
			t.Error("delivered notification still appeared as pending")
		}
	}

	// PurgeDeliveredNotifications only removes delivered rows older
	// than maxAge -- a maxAge of 0 means "older than now", so this
	// just-delivered row is a candidate immediately.
	purged, err := db.PurgeDeliveredNotifications(ctx, 0, 100)
	if err != nil {
		t.Fatalf("PurgeDeliveredNotifications: %v", err)
	}
	if purged < 1 {
		t.Errorf("PurgeDeliveredNotifications purged %d rows, want at least 1", purged)
	}
}
