-- Revocation policy (see internal/revokepolicy): a small, fixed
-- enumerated action per named signal (ip_changed, user_agent_changed,
-- inactivity_exceeded) -- deliberately not a general rule engine/DSL,
-- see docs/threat-model.md's own scope-discipline notes elsewhere in
-- this schema. Layered override: an explicit per-session
-- (authorizations) setting wins over a per-application setting, which
-- wins over the deployment-wide config default -- NULL at either
-- database layer means "inherit from above", not "off"; off must be
-- set explicitly to actually disable a signal.
ALTER TABLE applications ADD COLUMN revoke_policy_ip_changed TEXT
    CHECK (revoke_policy_ip_changed IN ('off', 'warn', 'flag_for_review', 'revoke'));
ALTER TABLE applications ADD COLUMN revoke_policy_user_agent_changed TEXT
    CHECK (revoke_policy_user_agent_changed IN ('off', 'warn', 'flag_for_review', 'revoke'));
ALTER TABLE applications ADD COLUMN revoke_policy_inactivity_exceeded TEXT
    CHECK (revoke_policy_inactivity_exceeded IN ('off', 'warn', 'flag_for_review', 'revoke'));

ALTER TABLE authorizations ADD COLUMN revoke_policy_ip_changed TEXT
    CHECK (revoke_policy_ip_changed IN ('off', 'warn', 'flag_for_review', 'revoke'));
ALTER TABLE authorizations ADD COLUMN revoke_policy_user_agent_changed TEXT
    CHECK (revoke_policy_user_agent_changed IN ('off', 'warn', 'flag_for_review', 'revoke'));
ALTER TABLE authorizations ADD COLUMN revoke_policy_inactivity_exceeded TEXT
    CHECK (revoke_policy_inactivity_exceeded IN ('off', 'warn', 'flag_for_review', 'revoke'));

-- "flag_for_review" is a first-class, visible "needs attention" state,
-- deliberately distinct from revoked_at: access stays allowed (an
-- unattended display that lost its network for an afternoon shouldn't
-- go dark with no one around to notice) until an administrator or
-- ApplicationOwner reviews and clears it, or a later signal escalates
-- to an actual revoke.
ALTER TABLE authorizations ADD COLUMN flagged_at TIMESTAMPTZ;
ALTER TABLE authorizations ADD COLUMN flagged_reason TEXT;
