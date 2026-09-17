-- Bounded, encrypted claim-retry envelope (spec section 5): the only
-- permitted database exception to hash-only credential storage, since it
-- must hold a raw, reissuable credential for a short retry window.
CREATE TABLE claim_results (
    request_id UUID PRIMARY KEY REFERENCES approval_requests (id),
    credential_id UUID NOT NULL REFERENCES credentials (id),
    encryption_key_id TEXT NOT NULL,
    nonce BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
