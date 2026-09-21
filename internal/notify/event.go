package notify

import "time"

// EventRequestCreated is notification_outbox.event_type's only value
// today (spec-adjacent design, not spec-mandated -- see this package's
// own doc comment). Kept as a named constant, not a bare string, since
// internal/enrollment (the producer) and this package's delivery job
// (the consumer) must agree on it exactly.
const EventRequestCreated = "request.created"

// RequestCreatedPayload is exactly what internal/enrollment marshals
// into notification_outbox.payload for EventRequestCreated -- request-
// specific fields only. Application hostname/display_name are
// deliberately NOT included here: the delivery job re-reads the
// application row fresh at delivery time anyway (to resolve its
// notify_email/notify_webhook_url), so baking in a possibly-stale
// display name at enqueue time would be redundant, not just extra
// bytes.
//
// Label/Message are deliberately NOT here (endpoint-review.md F3:
// "exclude anonymous message and label content from email and webhook
// notifications by default"). An anonymous, unauthenticated requester's
// own text has no place riding along in a notification an approver
// might read on a phone lock screen or a downstream automation might
// parse -- an approver reviews the actual submitted text (marked
// unverified) in the admin console itself, not in the notification
// that alerts them to look.
type RequestCreatedPayload struct {
	RequestID        string    `json:"request_id"`
	VerificationCode string    `json:"verification_code"`
	RequestedAt      time.Time `json:"requested_at"`
}

// Event is what a Dispatcher actually delivers -- a RequestCreatedPayload
// merged with the application fields resolved fresh at delivery time.
// AdminConsoleURL is built by the caller from the deployment's own
// configured admin origin (internal/notify.Config.AdminOrigin), never
// from anything requester-controlled.
type Event struct {
	Type                   string
	ApplicationHostname    string
	ApplicationDisplayName string
	RequestID              string
	VerificationCode       string
	RequestedAt            time.Time
	AdminConsoleURL        string
}

// webhookBody is the JSON body actually POSTed to a webhook -- a
// separate, explicitly-tagged type from Event so the wire shape is
// deliberate (snake_case, stable field names) rather than whatever
// Go's default json.Marshal of Event would happen to produce.
type webhookBody struct {
	Event                  string    `json:"event"`
	ApplicationHostname    string    `json:"application_hostname"`
	ApplicationDisplayName string    `json:"application_display_name"`
	RequestID              string    `json:"request_id,omitempty"`
	VerificationCode       string    `json:"verification_code,omitempty"`
	RequestedAt            time.Time `json:"requested_at,omitempty"`
	AdminConsoleURL        string    `json:"admin_console_url,omitempty"`
}

func newWebhookBody(e Event) webhookBody {
	return webhookBody{
		Event: e.Type, ApplicationHostname: e.ApplicationHostname, ApplicationDisplayName: e.ApplicationDisplayName,
		RequestID: e.RequestID, VerificationCode: e.VerificationCode, RequestedAt: e.RequestedAt, AdminConsoleURL: e.AdminConsoleURL,
	}
}
