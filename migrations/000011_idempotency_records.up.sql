CREATE TABLE idempotency_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_session_id UUID NOT NULL REFERENCES admin_sessions (id),
    key TEXT NOT NULL,
    operation TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    result_status INTEGER NOT NULL,
    result_body JSONB,
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT idempotency_records_request_hash_length CHECK (octet_length(request_hash) = 32)
);

CREATE UNIQUE INDEX idempotency_records_actor_key_operation_key
    ON idempotency_records (actor_session_id, key, operation);

CREATE INDEX idempotency_records_expires_at_idx ON idempotency_records (expires_at);
