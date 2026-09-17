CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_type TEXT NOT NULL,
    actor_subject TEXT,
    action TEXT NOT NULL,

    -- Nullable and ON DELETE SET NULL: retention purges of old requests,
    -- authorizations, or applications must not destroy audit history, only
    -- detach it (spec section 12).
    application_id UUID REFERENCES applications (id) ON DELETE SET NULL,
    request_id UUID REFERENCES approval_requests (id) ON DELETE SET NULL,
    authorization_id UUID REFERENCES authorizations (id) ON DELETE SET NULL,

    correlation_id UUID NOT NULL,
    source_ip INET,
    reason TEXT,
    redacted_before JSONB,
    redacted_after JSONB,
    outcome TEXT NOT NULL,

    CONSTRAINT audit_events_actor_type_check CHECK (actor_type IN ('admin', 'browser', 'system')),
    CONSTRAINT audit_events_outcome_check CHECK (outcome IN ('success', 'failure'))
);

CREATE INDEX audit_events_occurred_at_id_idx ON audit_events (occurred_at, id);
CREATE INDEX audit_events_application_occurred_idx ON audit_events (application_id, occurred_at);
