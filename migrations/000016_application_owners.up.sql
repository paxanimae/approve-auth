-- ApplicationOwner: a subject scoped to one or more specific
-- applications instead of the global administrator/viewer split.
-- Ownership is granted/revoked by an administrator only (see
-- internal/admin's Grant/RevokeApplicationOwner) and, like role itself,
-- is resolved fresh from this table on every request that needs it
-- (internal/httpserver's ownership checks) rather than snapshotted onto
-- the session row the way role is -- an admin revoking someone's
-- ownership takes effect immediately, not just on that owner's next
-- login. subject is the same stable OIDC subject every other actor
-- field in this schema uses, never a display name.
CREATE TABLE application_owners (
    application_id UUID NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (application_id, subject)
);

GRANT SELECT, INSERT, DELETE ON application_owners TO app_runtime;

-- Whether a subject can log in AT ALL as an application_owner (as
-- opposed to which specific application(s) they own, checked fresh per
-- request) is still resolved once at login and snapshotted the same
-- way administrator/viewer already are -- role itself follows the
-- existing convention; only the owned-application-id set is live.
ALTER TABLE admin_sessions DROP CONSTRAINT admin_sessions_role_check;
ALTER TABLE admin_sessions ADD CONSTRAINT admin_sessions_role_check
    CHECK (role IN ('viewer', 'administrator', 'application_owner'));
