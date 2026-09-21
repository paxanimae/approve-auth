package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paxanimae/approve-auth/internal/revokepolicy"
)

// FlagAuthorizationForReview marks authorizationID as needing a
// human's attention (revocation-policy action "flag_for_review") --
// access stays allowed; this only adds a first-class, visible "needs
// attention" state, deliberately not a hard revoke (an unattended
// display that tripped a signal shouldn't go dark with no one around
// to notice). Idempotent: flagging an already-flagged authorization is
// a no-op (no error, no duplicate audit event) -- the synchronous
// IP/UA-change check in internal/authz.Decide isn't itself
// deduplicated across requests within TouchLastSeen's own once-per-
// minute throttle, so this may be called more than once per episode.
func (db *DB) FlagAuthorizationForReview(ctx context.Context, authorizationID, applicationID uuid.UUID, reason string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: flagging authorization %s for review: begin: %w", authorizationID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE authorizations SET flagged_at = now(), flagged_reason = $2
		WHERE id = $1 AND flagged_at IS NULL`, authorizationID, nullableText(reason))
	if err != nil {
		return fmt.Errorf("store: flagging authorization %s for review: %w", authorizationID, err)
	}
	if tag.RowsAffected() > 0 {
		if err := insertAuditEvent(ctx, tx, auditParams{
			ActorType: "system", Action: "authorization.flagged_for_review",
			ApplicationID: &applicationID, AuthorizationID: &authorizationID, Reason: reason,
		}); err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: flagging authorization %s for review: commit: %w", authorizationID, err)
	}
	return nil
}

// ClearAuthorizationFlag lets an administrator or ApplicationOwner
// acknowledge a flagged_for_review state once reviewed -- it only
// clears the marker, never touches revoked_at/expires_at. Idempotent:
// clearing an authorization that isn't currently flagged (including
// one that doesn't exist) is a no-op, matching GrantApplicationOwner's
// own idempotent philosophy.
func (db *DB) ClearAuthorizationFlag(ctx context.Context, authorizationID uuid.UUID, clearedBy string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: clearing flag on authorization %s: begin: %w", authorizationID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var applicationID uuid.UUID
	err = tx.QueryRow(ctx, `
		UPDATE authorizations SET flagged_at = NULL, flagged_reason = NULL
		WHERE id = $1 AND flagged_at IS NOT NULL
		RETURNING application_id`, authorizationID).Scan(&applicationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return tx.Commit(ctx)
	}
	if err != nil {
		return fmt.Errorf("store: clearing flag on authorization %s: %w", authorizationID, err)
	}

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: clearedBy, Action: "authorization.flag_cleared",
		ApplicationID: &applicationID, AuthorizationID: &authorizationID,
	}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: clearing flag on authorization %s: commit: %w", authorizationID, err)
	}
	return nil
}

// RecordRevocationPolicyWarning writes a "warn"-tier revocation-policy
// audit event -- audit-only, access is unaffected. May fire more than
// once for a single continuous IP/UA-change episode, bounded by
// TouchLastSeen's own once-per-minute throttle (see
// internal/authz.Decide's own comment on why this isn't deduplicated
// further: each firing corresponds to a genuinely distinct request).
func (db *DB) RecordRevocationPolicyWarning(ctx context.Context, authorizationID, applicationID uuid.UUID, signal string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: recording policy warning for authorization %s: begin: %w", authorizationID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "system", Action: "authorization.policy_warning",
		ApplicationID: &applicationID, AuthorizationID: &authorizationID, Reason: signal,
	}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: recording policy warning for authorization %s: commit: %w", authorizationID, err)
	}
	return nil
}

// EnforceInactivityPolicy applies the InactivityExceeded revocation-
// policy signal to every active authorization whose last activity
// (last_seen_at, or approved_at if it's never actually been used) is
// older than threshold -- the out-of-path counterpart to Decide's own
// synchronous IP/UA-change checks, needed because a device that simply
// never reconnects would never trigger an in-path check at all.
// globalDefault is InactivityExceeded's deployment-wide default
// action; unlike IPChanged/UserAgentChanged, this signal's THRESHOLD
// is deliberately global-only, not layered per-application/session --
// a scope bound on this feature, not an oversight (see
// internal/config.Config.RevocationInactivityThreshold's own comment).
// Only the resulting ACTION is layered, via each row's own
// revoke_policy_inactivity_exceeded override columns.
func (db *DB) EnforceInactivityPolicy(ctx context.Context, globalDefault revokepolicy.Action, threshold time.Duration, limit int) (int, error) {
	cutoff := time.Now().Add(-threshold)
	rows, err := db.Pool.Query(ctx, `
		SELECT z.id, z.application_id, z.request_id, z.version,
		       z.revoke_policy_inactivity_exceeded, a.revoke_policy_inactivity_exceeded,
		       COALESCE(z.last_seen_at, z.approved_at)
		FROM authorizations z
		JOIN applications a ON a.id = z.application_id
		WHERE z.activated_at IS NOT NULL AND z.revoked_at IS NULL AND z.expires_at > now()
		  AND COALESCE(z.last_seen_at, z.approved_at) <= $1
		ORDER BY z.id
		LIMIT $2`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("store: enforcing inactivity policy: listing candidates: %w", err)
	}
	type inactivityCandidate struct {
		authID, appID, reqID         uuid.UUID
		version                      int32
		sessionOverride, appOverride *string
		lastActivity                 time.Time
	}
	var candidates []inactivityCandidate
	for rows.Next() {
		var c inactivityCandidate
		if err := rows.Scan(&c.authID, &c.appID, &c.reqID, &c.version, &c.sessionOverride, &c.appOverride, &c.lastActivity); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: enforcing inactivity policy: scanning: %w", err)
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: enforcing inactivity policy: %w", err)
	}

	affected := 0
	for _, c := range candidates {
		switch revokepolicy.Resolve(c.sessionOverride, c.appOverride, globalDefault) {
		case revokepolicy.ActionWarn:
			warned, err := db.recordInactivityWarningOnce(ctx, c.authID, c.appID, c.reqID, c.lastActivity)
			if err != nil {
				return affected, err
			}
			if warned {
				affected++
			}
		case revokepolicy.ActionFlagForReview:
			if err := db.FlagAuthorizationForReview(ctx, c.authID, c.appID, string(revokepolicy.SignalInactivityExceeded)); err != nil {
				return affected, err
			}
			affected++
		case revokepolicy.ActionRevoke:
			// A stale version means a concurrent admin action (renew,
			// an explicit revoke) already changed this row -- treat as
			// a harmless no-op rather than a hard failure; the next
			// tick re-evaluates it against whatever state it's in now.
			if err := db.RevokeAuthorization(ctx, c.authID, c.version, string(revokepolicy.SignalInactivityExceeded), "system:revoke-policy"); err != nil && !errors.Is(err, ErrConflict) {
				return affected, err
			}
			affected++
		default: // ActionOff, or an unrecognized/zero value
		}
	}
	return affected, nil
}

func (db *DB) recordInactivityWarningOnce(ctx context.Context, authorizationID, applicationID, requestID uuid.UUID, lastActivity time.Time) (bool, error) {
	var alreadyWarned bool
	if err := db.Pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM audit_events
			WHERE authorization_id = $1 AND action = 'authorization.inactivity_warned' AND occurred_at > $2
		)`, authorizationID, lastActivity).Scan(&alreadyWarned); err != nil {
		return false, fmt.Errorf("store: checking inactivity warning history for authorization %s: %w", authorizationID, err)
	}
	if alreadyWarned {
		return false, nil
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("store: recording inactivity warning for authorization %s: begin: %w", authorizationID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "system", Action: "authorization.inactivity_warned",
		ApplicationID: &applicationID, RequestID: &requestID, AuthorizationID: &authorizationID,
	}); err != nil {
		return false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("store: recording inactivity warning for authorization %s: commit: %w", authorizationID, err)
	}
	return true, nil
}
