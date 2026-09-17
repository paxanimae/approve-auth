CREATE TABLE approval_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications (id),
    pending_token_hash BYTEA NOT NULL,
    verification_code TEXT NOT NULL,
    label TEXT,
    message TEXT,
    return_path TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deadline_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ,
    decided_by TEXT,
    claim_deadline_at TIMESTAMPTZ,
    claimed_at TIMESTAMPTZ,
    public_decision_message TEXT,
    private_note TEXT,
    source_ip INET,
    user_agent TEXT,
    version INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT approval_requests_status_check
        CHECK (status IN ('pending', 'approved', 'denied', 'canceled', 'timed_out', 'claimed', 'claim_expired')),
    CONSTRAINT approval_requests_label_length CHECK (label IS NULL OR char_length(label) <= 100),
    CONSTRAINT approval_requests_message_length CHECK (message IS NULL OR char_length(message) <= 500),
    CONSTRAINT approval_requests_return_path_length CHECK (return_path IS NULL OR octet_length(return_path) <= 2048),
    CONSTRAINT approval_requests_token_hash_length CHECK (octet_length(pending_token_hash) = 32)
);

CREATE UNIQUE INDEX approval_requests_pending_token_hash_key ON approval_requests (pending_token_hash);

-- Composite unique anchor for authorizations' composite FK (see migration 4).
CREATE UNIQUE INDEX approval_requests_id_application_id_key ON approval_requests (id, application_id);

-- Verification codes are a comparison aid, not a secret, but must not
-- collide among currently-live requests (spec section 5).
CREATE UNIQUE INDEX approval_requests_live_verification_code_key
    ON approval_requests (verification_code)
    WHERE status IN ('pending', 'approved');

CREATE INDEX approval_requests_application_status_requested_idx
    ON approval_requests (application_id, status, requested_at);
