// Package notify delivers approval-flow notifications -- deliberately
// scoped to email and a generic outbound webhook only, never native
// SMS/MQTT clients (see docs/threat-model.md's own scope-discipline
// notes) -- for one event today: a new request needs approval.
//
// internal/store's notification_outbox table is the durable queue: a
// producer (internal/enrollment) enqueues an event as raw JSON in its
// own transaction-adjacent call, and this package's delivery job (run
// by internal/worker, wired up in cmd/server) polls, resolves each
// application's own notify_email/notify_webhook_url override or the
// service-wide default, and attempts delivery with exponential backoff
// on failure. Nothing here ever blocks or fails the request that
// triggered it -- a stuck SMTP relay or an unreachable webhook endpoint
// degrades notifications, not approvals.
package notify
