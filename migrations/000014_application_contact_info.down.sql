ALTER TABLE applications DROP CONSTRAINT IF EXISTS applications_contact_info_length;
ALTER TABLE applications DROP COLUMN IF EXISTS contact_info;
