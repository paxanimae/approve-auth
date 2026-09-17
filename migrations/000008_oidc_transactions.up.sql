CREATE TABLE oidc_transactions (
    state_hash BYTEA PRIMARY KEY,
    nonce TEXT NOT NULL,
    encrypted_pkce_verifier BYTEA NOT NULL,
    safe_return_path TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,

    CONSTRAINT oidc_transactions_state_hash_length CHECK (octet_length(state_hash) = 32),
    CONSTRAINT oidc_transactions_return_path_length CHECK (safe_return_path IS NULL OR octet_length(safe_return_path) <= 2048)
);
