CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    authorization_id UUID NOT NULL,
    application_id UUID NOT NULL REFERENCES applications (id),
    token_hash BYTEA NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT credentials_token_hash_length CHECK (octet_length(token_hash) = 32),

    -- Same application-consistency guarantee as authorizations: a credential
    -- cannot be issued against an authorization belonging to a different
    -- application than the credential claims.
    CONSTRAINT credentials_authorization_application_fk
        FOREIGN KEY (authorization_id, application_id)
        REFERENCES authorizations (id, application_id)
);

CREATE UNIQUE INDEX credentials_token_hash_key ON credentials (token_hash);
CREATE INDEX credentials_authorization_id_idx ON credentials (authorization_id);
