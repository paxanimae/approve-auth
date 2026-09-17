CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT true,
    default_duration_seconds INTEGER NOT NULL,
    max_duration_seconds INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_at TIMESTAMPTZ,
    version INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT applications_hostname_lowercase CHECK (hostname = lower(hostname)),
    CONSTRAINT applications_duration_positive CHECK (default_duration_seconds > 0 AND max_duration_seconds > 0),
    CONSTRAINT applications_duration_order CHECK (default_duration_seconds <= max_duration_seconds)
);

CREATE UNIQUE INDEX applications_hostname_key ON applications (hostname);

-- Composite unique anchor so later tables can carry a composite FK back to
-- (id, application_id) and have Postgres itself reject any row whose
-- application_id doesn't match its parent's.
ALTER TABLE applications ADD CONSTRAINT applications_id_key UNIQUE (id);

-- Hostnames are immutable after registration (spec section 3): replacing an
-- application to change its host, not editing hostname in place.
CREATE OR REPLACE FUNCTION applications_hostname_immutable() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.hostname <> OLD.hostname THEN
        RAISE EXCEPTION 'applications.hostname is immutable (got % -> %)', OLD.hostname, NEW.hostname;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER applications_hostname_immutable_trigger
    BEFORE UPDATE ON applications
    FOR EACH ROW
    EXECUTE FUNCTION applications_hostname_immutable();
