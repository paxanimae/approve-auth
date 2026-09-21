// Package revokepolicy holds the revocation policy's small, fixed
// vocabulary -- named signals and the actions they can resolve to --
// and the layered-override resolution rule every layer (internal/authz,
// the inactivity worker job, the admin API's validation) shares.
// Deliberately not a general rule engine or DSL: a fail-closed hot path
// (internal/authz.Decide) is not the place to add an expression
// language, see docs/threat-model.md's own scope-discipline notes
// elsewhere in this schema.
package revokepolicy

// Signal names a fixed, named revocation-policy trigger. Also the
// audit_events.reason value a firing signal writes, and (via
// migration 000018's CHECK constraints) the only three signals a
// nullable override column exists for -- there is no mechanism to add
// a signal without a migration, by design.
type Signal string

const (
	SignalIPChanged          Signal = "ip_changed"
	SignalUserAgentChanged   Signal = "user_agent_changed"
	SignalInactivityExceeded Signal = "inactivity_exceeded"
)

// Action is revocation-policy's response to a signal firing.
type Action string

const (
	// ActionOff explicitly disables a signal -- distinct from an unset
	// (nil) override, which means "inherit from the level above"
	// rather than "off": off must be set explicitly at whichever layer
	// means to turn a signal off.
	ActionOff Action = "off"
	// ActionWarn is audit-only: access is unaffected. May fire more
	// than once for one continuous change episode (see
	// internal/authz's own comment on why this isn't deduplicated
	// further -- it's bounded, not unbounded, and each firing is a
	// distinct real request).
	ActionWarn Action = "warn"
	// ActionFlagForReview keeps access allowed but sets a first-class,
	// visible "needs attention" marker (authorizations.flagged_at) --
	// added specifically because a hard revoke on an unattended
	// display just goes dark with no one around to notice.
	ActionFlagForReview Action = "flag_for_review"
	// ActionRevoke ends access. For IPChanged/UserAgentChanged this
	// must happen synchronously inside internal/authz.Decide itself
	// (the decision this same request is about to receive flips from
	// Allow to Deny) -- never advisory, unlike TouchLastSeen.
	ActionRevoke Action = "revoke"
)

// Valid reports whether a is one of the four recognized actions --
// matches migration 000018's CHECK constraints exactly, so a value
// read back from the database is always valid; this exists as defense
// in depth for values that didn't come from the database (e.g. a
// caller-supplied override before it's been validated and stored).
func (a Action) Valid() bool {
	switch a {
	case ActionOff, ActionWarn, ActionFlagForReview, ActionRevoke:
		return true
	default:
		return false
	}
}

// severity ranks actions so that when two independent signals fire on
// the same request (e.g. both IP and User-Agent changed, configured
// differently), Decide can apply the single more severe outcome --
// exactly one decision per request, never two.
func (a Action) severity() int {
	switch a {
	case ActionRevoke:
		return 3
	case ActionFlagForReview:
		return 2
	case ActionWarn:
		return 1
	default: // ActionOff, or an unrecognized value treated as off
		return 0
	}
}

// MoreSevere reports whether a outranks b.
func (a Action) MoreSevere(b Action) bool { return a.severity() > b.severity() }

// Resolve implements the layered override every caller shares: an
// explicit session-level setting wins, then an explicit application-
// level setting, then the deployment-wide default. A nil pointer at a
// given layer means "inherit from above" -- an invalid/unrecognized
// stored value (should be impossible under the CHECK constraint, but
// checked anyway) is treated the same as nil, falling through rather
// than resolving to a bogus action.
func Resolve(session, application *string, global Action) Action {
	if session != nil && Action(*session).Valid() {
		return Action(*session)
	}
	if application != nil && Action(*application).Valid() {
		return Action(*application)
	}
	return global
}
