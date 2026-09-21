package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AccessSnapshot is everything the authoritative check (spec section 3)
// needs, fetched in one query so the decision is made against a single
// consistent read of "now" rather than several. A nil *AccessSnapshot
// (with nil error) means the hostname itself is not registered -- the
// caller must treat this as "unknown host", distinct from "known host,
// no matching credential".
type AccessSnapshot struct {
	ApplicationID      uuid.UUID
	ApplicationEnabled bool

	CredentialFound             bool
	CredentialApplicationID     uuid.UUID
	CredentialRevoked           bool
	CredentialAbsoluteExpiresAt time.Time

	AuthorizationID        uuid.UUID
	AuthorizationVersion   int32
	AuthorizationRevoked   bool
	AuthorizationActivated bool
	AuthorizationExpiresAt time.Time

	// LastSeenIP/LastSeenUserAgent are the authorization's last-seen
	// values as of BEFORE this request's own TouchLastSeen write --
	// internal/authz.Decide compares req's own IP/UA against these to
	// detect the IPChanged/UserAgentChanged revocation-policy signals.
	// Both nil means no prior successful access to compare against
	// (this credential's first use), which must never fire a signal.
	LastSeenIP        *net.IP
	LastSeenUserAgent *string

	// RevokePolicy{IPChanged,UserAgentChanged}{App,Session} back
	// internal/revokepolicy.Resolve -- inactivity's own override
	// columns aren't needed here since InactivityExceeded is checked
	// out-of-path by a worker job, not synchronously in Decide.
	RevokePolicyIPChangedApp            *string
	RevokePolicyIPChangedSession        *string
	RevokePolicyUserAgentChangedApp     *string
	RevokePolicyUserAgentChangedSession *string

	// RevokePolicy{IPChanged,UserAgentChanged}Global are the current
	// deployment-wide defaults (migration 000019's global_settings,
	// live-editable from the admin console -- see
	// internal/revokepolicy.Resolve's own comment on why these can't
	// be fixed at Decide's construction time). Pulled in via a cross
	// join against that table's single row, so this stays one query.
	RevokePolicyIPChangedGlobal        string
	RevokePolicyUserAgentChangedGlobal string

	DatabaseNow time.Time
}

// GetAccessSnapshot looks up hostname's application and, in the same
// query, the credential matching credentialTokenHash (if any) and its
// authorization. Read from the primary: spec section 7 requires no
// positive-authorization cache and no lagging-replica reads.
func (db *DB) GetAccessSnapshot(ctx context.Context, hostname string, credentialTokenHash []byte) (*AccessSnapshot, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT
			a.id,
			a.enabled,
			c.id IS NOT NULL,
			c.application_id,
			COALESCE(c.revoked_at IS NOT NULL, false),
			c.absolute_expires_at,
			z.id,
			z.version,
			COALESCE(z.revoked_at IS NOT NULL, false),
			COALESCE(z.activated_at IS NOT NULL, false),
			z.expires_at,
			z.last_seen_ip,
			z.last_seen_user_agent,
			a.revoke_policy_ip_changed,
			z.revoke_policy_ip_changed,
			a.revoke_policy_user_agent_changed,
			z.revoke_policy_user_agent_changed,
			gs.revoke_policy_ip_changed,
			gs.revoke_policy_user_agent_changed,
			now()
		FROM applications a
		CROSS JOIN global_settings gs
		LEFT JOIN credentials c ON c.token_hash = $2
		LEFT JOIN authorizations z ON z.id = c.authorization_id
		WHERE a.hostname = $1`,
		hostname, credentialTokenHash,
	)

	var snap AccessSnapshot
	var credentialApplicationID *uuid.UUID
	var credentialAbsoluteExpiresAt *time.Time
	var authorizationID *uuid.UUID
	var authorizationVersion *int32
	var authorizationExpiresAt *time.Time

	err := row.Scan(
		&snap.ApplicationID,
		&snap.ApplicationEnabled,
		&snap.CredentialFound,
		&credentialApplicationID,
		&snap.CredentialRevoked,
		&credentialAbsoluteExpiresAt,
		&authorizationID,
		&authorizationVersion,
		&snap.AuthorizationRevoked,
		&snap.AuthorizationActivated,
		&authorizationExpiresAt,
		&snap.LastSeenIP,
		&snap.LastSeenUserAgent,
		&snap.RevokePolicyIPChangedApp,
		&snap.RevokePolicyIPChangedSession,
		&snap.RevokePolicyUserAgentChangedApp,
		&snap.RevokePolicyUserAgentChangedSession,
		&snap.RevokePolicyIPChangedGlobal,
		&snap.RevokePolicyUserAgentChangedGlobal,
		&snap.DatabaseNow,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: access snapshot for %q: %w", hostname, err)
	}

	if credentialApplicationID != nil {
		snap.CredentialApplicationID = *credentialApplicationID
	}
	if credentialAbsoluteExpiresAt != nil {
		snap.CredentialAbsoluteExpiresAt = *credentialAbsoluteExpiresAt
	}
	if authorizationID != nil {
		snap.AuthorizationID = *authorizationID
	}
	if authorizationVersion != nil {
		snap.AuthorizationVersion = *authorizationVersion
	}
	if authorizationExpiresAt != nil {
		snap.AuthorizationExpiresAt = *authorizationExpiresAt
	}
	return &snap, nil
}

// TouchLastSeen coalesces last-seen writes to at most once per minute per
// authorization (spec section 8): the conditional UPDATE is a no-op, not
// an error, when the last write was recent. Last seen is advisory --
// callers must not treat its failure as fatal to the request it's
// attached to (spec section 8: "authorization correctness must not
// depend on it").
func (db *DB) TouchLastSeen(ctx context.Context, authorizationID uuid.UUID, clientIP, userAgent string) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE authorizations
		SET last_seen_at = now(), last_seen_ip = $2, last_seen_user_agent = $3
		WHERE id = $1
		  AND (last_seen_at IS NULL OR last_seen_at < now() - interval '1 minute')`,
		authorizationID, nullableInet(clientIP), nullableText(userAgent),
	)
	if err != nil {
		return fmt.Errorf("store: touching last seen for authorization %s: %w", authorizationID, err)
	}
	return nil
}

// RevokeByCredentialHash implements the browser-initiated logout (spec
// section 9's POST /logout: "Revoke own authorization and clear access/
// pending cookies"). A hostname that doesn't match the credential's own
// application, or a hash that matches nothing, is a silent no-op --
// logout always looks successful from the browser's side either way,
// since the cookies get cleared regardless.
func (db *DB) RevokeByCredentialHash(ctx context.Context, hostname string, tokenHash []byte, revokedBy string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: logout: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var authorizationID, applicationID, requestID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT z.id, z.application_id, z.request_id
		FROM credentials c
		JOIN authorizations z ON z.id = c.authorization_id
		JOIN applications a ON a.id = c.application_id
		WHERE c.token_hash = $1 AND a.hostname = $2 AND z.revoked_at IS NULL`,
		tokenHash, hostname,
	).Scan(&authorizationID, &applicationID, &requestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: logout: looking up credential: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE authorizations SET revoked_at = now(), revoked_by = $2, revocation_reason = 'logout', version = version + 1
		WHERE id = $1`, authorizationID, revokedBy); err != nil {
		return fmt.Errorf("store: logout: revoking authorization: %w", err)
	}
	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "browser", Action: "authorization.revoked",
		ApplicationID: &applicationID, RequestID: &requestID, AuthorizationID: &authorizationID, Reason: "logout",
	}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: logout: commit: %w", err)
	}
	return nil
}

func nullableInet(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nilIfEmptyStringPtr normalizes a caller-supplied *string where an
// explicit empty string and nil both mean "no value" -- used for the
// revoke-policy override columns, whose CHECK constraint would reject
// an empty string outright.
func nilIfEmptyStringPtr(p *string) *string {
	if p != nil && *p == "" {
		return nil
	}
	return p
}
