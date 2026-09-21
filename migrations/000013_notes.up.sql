-- Append-only notes on a request or an authorization (session) --
-- deliberately never editable/deletable through the app (matches this
-- schema's existing audit-immutability philosophy: app_runtime below
-- gets SELECT/INSERT only, no UPDATE/DELETE). ON DELETE CASCADE, not
-- SET NULL like audit_events' nullable FKs: a note has no independent
-- meaning once its parent request/authorization is gone (e.g. purged
-- by retention), unlike a general audit event.
CREATE TABLE request_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES approval_requests (id) ON DELETE CASCADE,
    author_subject TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT request_notes_body_length CHECK (char_length(body) BETWEEN 1 AND 2000)
);

CREATE INDEX request_notes_request_id_created_at_idx ON request_notes (request_id, created_at);

CREATE TABLE authorization_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    authorization_id UUID NOT NULL REFERENCES authorizations (id) ON DELETE CASCADE,
    author_subject TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT authorization_notes_body_length CHECK (char_length(body) BETWEEN 1 AND 2000)
);

CREATE INDEX authorization_notes_authorization_id_created_at_idx ON authorization_notes (authorization_id, created_at);

-- Same runtime/maintenance role split as migration 000012 -- app_runtime
-- can append and read but never update or delete a note directly (a
-- CASCADE delete from the parent row doesn't need this role to hold
-- its own DELETE privilege on these tables). Migration 000012 is
-- already applied in any real deployment and must never be edited
-- retroactively, so the new tables' grants live here instead.
GRANT SELECT, INSERT ON request_notes, authorization_notes TO app_runtime;
