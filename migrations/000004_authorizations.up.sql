CREATE TABLE authorizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications (id),
    request_id UUID NOT NULL UNIQUE,
    label TEXT,
    approved_by TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT,
    revocation_reason TEXT,
    last_seen_at TIMESTAMPTZ,
    last_seen_ip INET,
    last_seen_user_agent TEXT,
    version INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT authorizations_label_length CHECK (label IS NULL OR char_length(label) <= 100),

    -- The database itself rejects an authorization whose application_id
    -- doesn't match the application_id of the request it was created from
    -- (spec section 8: "enforce application consistency ... using composite
    -- foreign keys"). This is the core anti-cross-application-leak guarantee.
    CONSTRAINT authorizations_request_application_fk
        FOREIGN KEY (request_id, application_id)
        REFERENCES approval_requests (id, application_id)
);

-- Composite unique anchor for credentials' composite FK (see migration 5).
CREATE UNIQUE INDEX authorizations_id_application_id_key ON authorizations (id, application_id);

CREATE INDEX authorizations_active_expiry_idx
    ON authorizations (application_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX authorizations_last_seen_at_idx ON authorizations (last_seen_at);
