package store

import (
	"context"
	"errors"
	"fmt"
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
	AuthorizationRevoked   bool
	AuthorizationActivated bool
	AuthorizationExpiresAt time.Time

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
			COALESCE(z.revoked_at IS NOT NULL, false),
			COALESCE(z.activated_at IS NOT NULL, false),
			z.expires_at,
			now()
		FROM applications a
		LEFT JOIN credentials c ON c.token_hash = $2
		LEFT JOIN authorizations z ON z.id = c.authorization_id
		WHERE a.hostname = $1`,
		hostname, credentialTokenHash,
	)

	var snap AccessSnapshot
	var credentialApplicationID *uuid.UUID
	var credentialAbsoluteExpiresAt *time.Time
	var authorizationID *uuid.UUID
	var authorizationExpiresAt *time.Time

	err := row.Scan(
		&snap.ApplicationID,
		&snap.ApplicationEnabled,
		&snap.CredentialFound,
		&credentialApplicationID,
		&snap.CredentialRevoked,
		&credentialAbsoluteExpiresAt,
		&authorizationID,
		&snap.AuthorizationRevoked,
		&snap.AuthorizationActivated,
		&authorizationExpiresAt,
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
