-- Approval-flow notifications (email + generic outbound webhook only --
-- deliberately not a general rule engine or a native SMS/MQTT client,
-- see docs/threat-model.md's own notes on scope discipline elsewhere in
-- this schema). notify_email/notify_webhook_url are nullable per-
-- application overrides of the global config default, same pattern as
-- migration 000014's contact_info: NULL means "inherit the service-wide
-- default", not "notifications disabled for this application" -- there
-- is no per-application opt-out short of clearing both the override AND
-- the global default.
ALTER TABLE applications ADD COLUMN notify_email TEXT;
ALTER TABLE applications ADD COLUMN notify_webhook_url TEXT;

-- A durable outbox, not a fire-and-forget goroutine: enqueuing survives
-- a crash between "the request was created" and "the notification was
-- sent", and delivery is retried with backoff rather than attempted
-- once. delivered_at IS NULL is the pending-work marker; the partial
-- index keeps the delivery job's own query cheap regardless of how many
-- already-delivered rows have accumulated.
CREATE TABLE notification_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    last_error TEXT
);

CREATE INDEX notification_outbox_pending_idx ON notification_outbox (next_attempt_at) WHERE delivered_at IS NULL;

-- Unlike audit_events, this table has no immutability requirement --
-- it's operational delivery bookkeeping, not an audit trail, so the
-- runtime role manages its own rows end to end (enqueue, mark
-- delivered/failed, and purge its own old delivered rows), the same
-- grant shape migration 000012 already uses for rate_limit_buckets/
-- idempotency_records.
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_outbox TO app_runtime;
