-- endpoint-review.md F5: "free-text retention should be independent of
-- access-record retention." An approval request's label/message
-- currently follows the whole request record's lifecycle (up to 90
-- days after termination, or as long as a live authorization it backs
-- stays active -- up to a year). Anonymous, unverified free text has no
-- reason to outlive that; a short, independently configurable window
-- redacts just the label/message fields while the request/audit
-- records keep their own existing retention.
--
-- 30 days matches the existing ip_and_user_agent redaction window
-- (internal/config.Retention.IPAndUserAgent) as a reasonable "short"
-- default, not because the two are coupled -- this is its own setting,
-- editable independently from the admin console's Settings page like
-- every other business rule in this table.
ALTER TABLE global_settings ADD COLUMN message_retention_seconds INTEGER NOT NULL DEFAULT 2592000
    CHECK (message_retention_seconds > 0);
