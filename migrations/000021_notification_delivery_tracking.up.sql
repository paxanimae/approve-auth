-- endpoint-review.md F4: "notifications amplify abuse and retain
-- failed messages indefinitely." Two independent gaps:
--
-- 1. Dispatcher.Deliver only ever reported one joined error for both
--    channels, so a retry after a partial failure (e.g. email
--    succeeded, webhook still failing) resent the channel that had
--    already succeeded. email_delivered_at/webhook_delivered_at track
--    each channel's own outcome so a retry only ever attempts what
--    hasn't already succeeded.
-- 2. Retries backed off forever with no maximum age or attempt count,
--    so a row whose destination is permanently gone (or whose
--    application was deleted mid-flight) would sit retrying, and
--    retaining its payload, indefinitely. giveup_at marks a row the
--    delivery job has stopped retrying -- delivered_at stays NULL
--    (this was never actually delivered), but it's excluded from
--    ListPendingNotifications going forward, and its payload is
--    replaced with an empty object at that point.
ALTER TABLE notification_outbox ADD COLUMN email_delivered_at TIMESTAMPTZ;
ALTER TABLE notification_outbox ADD COLUMN webhook_delivered_at TIMESTAMPTZ;
ALTER TABLE notification_outbox ADD COLUMN giveup_at TIMESTAMPTZ;

DROP INDEX notification_outbox_pending_idx;
CREATE INDEX notification_outbox_pending_idx ON notification_outbox (next_attempt_at) WHERE delivered_at IS NULL AND giveup_at IS NULL;
