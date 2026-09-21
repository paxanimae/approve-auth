ALTER TABLE admin_sessions DROP CONSTRAINT admin_sessions_role_check;
ALTER TABLE admin_sessions ADD CONSTRAINT admin_sessions_role_check
    CHECK (role IN ('viewer', 'administrator'));

REVOKE ALL PRIVILEGES ON application_owners FROM app_runtime;
DROP TABLE IF EXISTS application_owners;
