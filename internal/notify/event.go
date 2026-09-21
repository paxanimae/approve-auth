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
type RequestCreatedPayload struct {
	RequestID        string    `json:"request_id"`
	VerificationCode string    `json:"verification_code"`
	Label            string    `json:"label,omitempty"`
	Message          string    `json:"message,omitempty"`
	RequestedAt      time.Time `json:"requested_at"`
}

// Event is what a Dispatcher actually delivers -- a RequestCreatedPayload
// merged with the application fields resolved fresh at delivery time.
type Event struct {
	Type                   string
	ApplicationHostname    string
	ApplicationDisplayName string
	RequestID              string
	VerificationCode       string
	Label                  string
	Message                string
	RequestedAt            time.Time
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
	Label                  string    `json:"label,omitempty"`
	Message                string    `json:"message,omitempty"`
	RequestedAt            time.Time `json:"requested_at,omitempty"`
}

func newWebhookBody(e Event) webhookBody {
	return webhookBody{
		Event: e.Type, ApplicationHostname: e.ApplicationHostname, ApplicationDisplayName: e.ApplicationDisplayName,
		RequestID: e.RequestID, VerificationCode: e.VerificationCode, Label: e.Label, Message: e.Message, RequestedAt: e.RequestedAt,
	}
}
