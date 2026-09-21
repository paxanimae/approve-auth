DROP TABLE notification_outbox;
ALTER TABLE applications DROP COLUMN notify_webhook_url;
ALTER TABLE applications DROP COLUMN notify_email;
