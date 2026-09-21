-- Per-application override of the global contact_info nonsecret config
-- value (deploy/approve-auth-config.example.yaml): shown on the request
-- page so an unattended device's operator knows who to reach about
-- access. NULL (never an empty string -- the store layer normalizes
-- "" to NULL on write) means "use the global default".
ALTER TABLE applications ADD COLUMN contact_info TEXT;

ALTER TABLE applications ADD CONSTRAINT applications_contact_info_length
    CHECK (contact_info IS NULL OR char_length(contact_info) <= 500);
