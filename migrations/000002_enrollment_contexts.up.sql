CREATE TABLE enrollment_contexts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications (id),
    pending_token_hash BYTEA NOT NULL,
    csrf_secret BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,

    CONSTRAINT enrollment_contexts_token_hash_length CHECK (octet_length(pending_token_hash) = 32)
);

CREATE UNIQUE INDEX enrollment_contexts_pending_token_hash_key ON enrollment_contexts (pending_token_hash);
CREATE INDEX enrollment_contexts_application_id_idx ON enrollment_contexts (application_id);
