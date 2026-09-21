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

// TestNotificationOutbox_ChannelTrackingAndGiveUp covers endpoint-
// review.md F4: per-channel delivery is tracked independently of the
// row's own overall delivered_at, and a given-up row is excluded from
// ListPendingNotifications with its payload redacted.
func TestNotificationOutbox_ChannelTrackingAndGiveUp(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "notify-outbox-channels.example.test")
	appUUID := uuid.MustParse(appID)

	if err := db.EnqueueNotification(ctx, appUUID, "request.created", []byte(`{"request_id":"r-2"}`)); err != nil {
		t.Fatalf("EnqueueNotification: %v", err)
	}
	pending, err := db.ListPendingNotifications(ctx, 100)
	if err != nil {
		t.Fatalf("ListPendingNotifications: %v", err)
	}
	var itemID uuid.UUID
	for _, p := range pending {
		if p.ApplicationID == appUUID {
			itemID = p.ID
			if p.EmailDeliveredAt != nil || p.WebhookDeliveredAt != nil {
				t.Errorf("a fresh row must not already have a per-channel delivery time: %+v", p)
			}
		}
	}
	if itemID == uuid.Nil {
		t.Fatal("enqueued notification did not appear in ListPendingNotifications")
	}

	if err := db.MarkNotificationChannelDelivered(ctx, itemID, "email"); err != nil {
		t.Fatalf("MarkNotificationChannelDelivered(email): %v", err)
	}
	afterEmail, err := db.ListPendingNotifications(ctx, 100)
	if err != nil {
		t.Fatalf("ListPendingNotifications (after email delivered): %v", err)
	}
	var sawEmailDeliveredAt bool
	for _, p := range afterEmail {
		if p.ID == itemID {
			sawEmailDeliveredAt = p.EmailDeliveredAt != nil
			if p.WebhookDeliveredAt != nil {
				t.Error("webhook channel must not be marked delivered by marking email delivered")
			}
		}
	}
	if !sawEmailDeliveredAt {
		t.Error("expected email_delivered_at to be set, and the row to still be pending overall (webhook not yet done)")
	}

	if err := db.GiveUpOnNotification(ctx, itemID, "exceeded max retry budget"); err != nil {
		t.Fatalf("GiveUpOnNotification: %v", err)
	}
	afterGiveUp, err := db.ListPendingNotifications(ctx, 100)
	if err != nil {
		t.Fatalf("ListPendingNotifications (after giveup): %v", err)
	}
	for _, p := range afterGiveUp {
		if p.ID == itemID {
			t.Error("a given-up row must not appear as pending any longer")
		}
	}

	var payload []byte
	if err := conn.QueryRow(ctx, `SELECT payload FROM notification_outbox WHERE id = $1`, itemID).Scan(&payload); err != nil {
		t.Fatalf("reading payload after giveup: %v", err)
	}
	if string(payload) != "{}" {
		t.Errorf("payload after giveup = %s, want the redacted empty object", payload)
	}

	// A given-up row is as terminal as a delivered one for retention
	// purposes.
	purged, err := db.PurgeDeliveredNotifications(ctx, 0, 100)
	if err != nil {
		t.Fatalf("PurgeDeliveredNotifications: %v", err)
	}
	if purged < 1 {
		t.Errorf("PurgeDeliveredNotifications purged %d rows, want at least 1 (the given-up row)", purged)
	}
}
