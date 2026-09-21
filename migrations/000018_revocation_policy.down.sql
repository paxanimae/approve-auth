ALTER TABLE authorizations DROP COLUMN flagged_reason;
ALTER TABLE authorizations DROP COLUMN flagged_at;

ALTER TABLE authorizations DROP COLUMN revoke_policy_inactivity_exceeded;
ALTER TABLE authorizations DROP COLUMN revoke_policy_user_agent_changed;
ALTER TABLE authorizations DROP COLUMN revoke_policy_ip_changed;

ALTER TABLE applications DROP COLUMN revoke_policy_inactivity_exceeded;
ALTER TABLE applications DROP COLUMN revoke_policy_user_agent_changed;
ALTER TABLE applications DROP COLUMN revoke_policy_ip_changed;
