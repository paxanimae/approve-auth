CREATE TABLE admin_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash BYTEA NOT NULL,
    oidc_issuer TEXT NOT NULL,
    oidc_subject TEXT NOT NULL,
    display_name TEXT,
    role TEXT NOT NULL,
    role_snapshot_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    csrf_secret BYTEA NOT NULL,

    CONSTRAINT admin_sessions_role_check CHECK (role IN ('viewer', 'administrator')),
    CONSTRAINT admin_sessions_token_hash_length CHECK (octet_length(token_hash) = 32)
);

CREATE UNIQUE INDEX admin_sessions_token_hash_key ON admin_sessions (token_hash);

-- Supports the "revoke sessions by issuer/subject" CLI command (spec
-- section 9's admin identity/roles requirement).
CREATE INDEX admin_sessions_issuer_subject_idx ON admin_sessions (oidc_issuer, oidc_subject);
