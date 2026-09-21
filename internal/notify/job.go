package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/store"
)

// JobStore is the internal/store.DB surface DeliverPending needs.
type JobStore interface {
	ListPendingNotifications(ctx context.Context, limit int) ([]store.NotificationOutboxItem, error)
	GetApplicationByID(ctx context.Context, id uuid.UUID) (store.Application, bool, error)
	MarkNotificationDelivered(ctx context.Context, id uuid.UUID) error
	MarkNotificationFailed(ctx context.Context, id uuid.UUID, nextAttemptAt time.Time, lastError string) error

	// GetGlobalSettings resolves EmailFrom/the two default
	// destinations -- called once per DeliverPending batch, not per
	// item, so an administrator's edit via the Settings page takes
	// effect on the next tick without needing a per-item query.
	GetGlobalSettings(ctx context.Context) (store.GlobalSettings, error)
}

// backoffSchedule caps retry growth at maxBackoff instead of doubling
// without bound -- a webhook endpoint that's down for hours should be
// retried periodically, never abandoned or hammered.
var backoffSchedule = []time.Duration{
	1 * time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute,
}

const maxBackoff = time.Hour

func backoffFor(attempts int) time.Duration {
	if attempts < len(backoffSchedule) {
		return backoffSchedule[attempts]
	}
	return maxBackoff
}

// DeliverPending attempts delivery of up to limit pending
// notification_outbox rows, returning how many were successfully
// delivered (including any with nothing configured to deliver to at
// all, which Deliver treats as a vacuous success -- see its own
// comment). One row's failure never stops the batch; it's recorded via
// MarkNotificationFailed and retried on backoffFor's schedule. Intended
// to be called from a worker.Job wrapping it in cmd/server, guarded by
// the same per-job advisory lock every other retention job uses, so no
// two replicas ever race to deliver the same row.
func (d *Dispatcher) DeliverPending(ctx context.Context, s JobStore, limit int) (int, error) {
	items, err := s.ListPendingNotifications(ctx, limit)
	if err != nil {
		return 0, fmt.Errorf("notify: listing pending notifications: %w", err)
	}
	if len(items) == 0 {
		return 0, nil
	}

	// Resolved once per batch, not per item -- see JobStore's own
	// comment on why.
	settings, err := s.GetGlobalSettings(ctx)
	if err != nil {
		return 0, fmt.Errorf("notify: loading global settings: %w", err)
	}

	delivered := 0
	for _, item := range items {
		app, found, err := s.GetApplicationByID(ctx, item.ApplicationID)
		if err != nil || !found {
			// The application row is gone -- its own ON DELETE CASCADE
			// would already have removed this outbox row too, so this
			// is defensive, not an expected path. Nothing sensible to
			// deliver to; back off at the ceiling rather than retrying
			// fast forever on a row that can never succeed.
			_ = s.MarkNotificationFailed(ctx, item.ID, time.Now().Add(maxBackoff), "application not found")
			continue
		}

		event, err := buildEvent(item, app)
		if err != nil {
			_ = s.MarkNotificationFailed(ctx, item.ID, time.Now().Add(maxBackoff), err.Error())
			continue
		}

		dest := Destination{
			Email:      resolveOverride(app.NotifyEmail, derefOrEmpty(settings.NotifyDefaultEmail)),
			WebhookURL: resolveOverride(app.NotifyWebhookURL, derefOrEmpty(settings.NotifyDefaultWebhookURL)),
		}

		attemptCtx, cancel := context.WithTimeout(ctx, deliveryTimeout)
		deliverErr := d.Deliver(attemptCtx, derefOrEmpty(settings.NotifyEmailFrom), dest, event)
		cancel()
		if deliverErr != nil {
			_ = s.MarkNotificationFailed(ctx, item.ID, time.Now().Add(backoffFor(item.Attempts)), deliverErr.Error())
			continue
		}
		if err := s.MarkNotificationDelivered(ctx, item.ID); err != nil {
			return delivered, fmt.Errorf("notify: marking notification %s delivered: %w", item.ID, err)
		}
		delivered++
	}
	return delivered, nil
}

// resolveOverride returns override's value if it's non-nil (regardless
// of content -- an explicit "" clears the field to "no destination",
// distinct from "inherit the default" which is nil), otherwise def.
func resolveOverride(override *string, def string) string {
	if override != nil {
		return *override
	}
	return def
}

// derefOrEmpty returns "" for a nil pointer -- global_settings'
// nullable fields (migration 000019) come back this way when unset.
func derefOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// buildEvent unmarshals item's payload according to its event_type and
// merges in app's own fields, freshly read at delivery time (see
// RequestCreatedPayload's own comment on why hostname/display_name
// aren't baked into the stored payload).
func buildEvent(item store.NotificationOutboxItem, app store.Application) (Event, error) {
	switch item.EventType {
	case EventRequestCreated:
		var p RequestCreatedPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return Event{}, fmt.Errorf("unmarshaling %s payload: %w", item.EventType, err)
		}
		return Event{
			Type: item.EventType, ApplicationHostname: app.Hostname, ApplicationDisplayName: app.DisplayName,
			RequestID: p.RequestID, VerificationCode: p.VerificationCode, Label: p.Label, Message: p.Message, RequestedAt: p.RequestedAt,
		}, nil
	default:
		return Event{}, fmt.Errorf("unknown notification event type %q", item.EventType)
	}
}
