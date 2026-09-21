DROP INDEX notification_outbox_pending_idx;
CREATE INDEX notification_outbox_pending_idx ON notification_outbox (next_attempt_at) WHERE delivered_at IS NULL;

ALTER TABLE notification_outbox DROP COLUMN email_delivered_at;
ALTER TABLE notification_outbox DROP COLUMN webhook_delivered_at;
ALTER TABLE notification_outbox DROP COLUMN giveup_at;
