-- Global settings: the deployment-wide business-rule defaults that used
-- to live in the static YAML config -- contact_info, notification
-- recipients/content, and the revocation-policy defaults + inactivity
-- threshold. Deliberately NOT in config anymore: these are business
-- rules an administrator should be able to change live, from the admin
-- console's Settings page, without a redeploy. What legitimately stays
-- in static config is infrastructure/credentials (SMTP transport
-- host/port/username, the two notification secrets, TLS/OIDC/listener
-- settings) -- see internal/config.Config's own comments.
--
-- Singleton row: the `singleton` PK with a CHECK forcing it to always
-- be `true` means Postgres itself rejects a second row outright: this
-- table is never queried by any key other than "the one row", so a
-- second row would just be silent dead data with no way to reach it.
CREATE TABLE global_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),

    contact_info TEXT,
    notify_email_from TEXT,
    notify_default_email TEXT,
    notify_default_webhook_url TEXT,

    revoke_policy_ip_changed TEXT NOT NULL DEFAULT 'flag_for_review'
        CHECK (revoke_policy_ip_changed IN ('off', 'warn', 'flag_for_review', 'revoke')),
    revoke_policy_user_agent_changed TEXT NOT NULL DEFAULT 'warn'
        CHECK (revoke_policy_user_agent_changed IN ('off', 'warn', 'flag_for_review', 'revoke')),
    revoke_policy_inactivity_exceeded TEXT NOT NULL DEFAULT 'off'
        CHECK (revoke_policy_inactivity_exceeded IN ('off', 'warn', 'flag_for_review', 'revoke')),
    -- 90 days, matching the previous config default.
    revocation_inactivity_threshold_seconds INTEGER NOT NULL DEFAULT 7776000
        CHECK (revocation_inactivity_threshold_seconds > 0),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version INTEGER NOT NULL DEFAULT 1
);

-- Seeded once, here, under this migration's own privileged connection --
-- app_runtime never gets INSERT/DELETE on this table, only SELECT/UPDATE,
-- since the row is never created or removed after this point.
INSERT INTO global_settings (singleton) VALUES (true);

GRANT SELECT, UPDATE ON global_settings TO app_runtime;
