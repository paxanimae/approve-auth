package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateAdminSession persists a freshly logged-in admin session (spec
// section 9). role is a snapshot taken now from the OIDC groups claim --
// spec section 9: "Group changes apply at reauthentication," so this
// isn't re-checked until the next login.
func (db *DB) CreateAdminSession(ctx context.Context, oidcIssuer, oidcSubject, displayName, role string, tokenHash, csrfSecret []byte, absoluteExpiresAt time.Time) (AdminSession, error) {
	var s AdminSession
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO admin_sessions (token_hash, oidc_issuer, oidc_subject, display_name, role, absolute_expires_at, csrf_secret)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, token_hash, oidc_issuer, oidc_subject, display_name, role, role_snapshot_at, created_at, last_seen_at, absolute_expires_at, revoked_at, csrf_secret`,
		tokenHash, oidcIssuer, oidcSubject, nullableText(displayName), role, absoluteExpiresAt, csrfSecret,
	).Scan(
		&s.ID, &s.TokenHash, &s.OIDCIssuer, &s.OIDCSubject, &s.DisplayName, &s.Role,
		&s.RoleSnapshotAt, &s.CreatedAt, &s.LastSeenAt, &s.AbsoluteExpiresAt, &s.RevokedAt, &s.CSRFSecret,
	)
	if err != nil {
		return AdminSession{}, fmt.Errorf("store: creating admin session: %w", err)
	}
	return s, nil
}

// GetLiveAdminSessionByTokenHash checks revocation and the absolute
// expiry only -- idle-timeout is a caller-side check against LastSeenAt
// (spec section 14's ADMIN_IDLE_TTL is config, not schema).
func (db *DB) GetLiveAdminSessionByTokenHash(ctx context.Context, hash []byte) (AdminSession, bool, error) {
	var s AdminSession
	err := db.Pool.QueryRow(ctx, `
		SELECT id, token_hash, oidc_issuer, oidc_subject, display_name, role, role_snapshot_at, created_at, last_seen_at, absolute_expires_at, revoked_at, csrf_secret
		FROM admin_sessions
		WHERE token_hash = $1 AND revoked_at IS NULL AND absolute_expires_at > now()`, hash,
	).Scan(
		&s.ID, &s.TokenHash, &s.OIDCIssuer, &s.OIDCSubject, &s.DisplayName, &s.Role,
		&s.RoleSnapshotAt, &s.CreatedAt, &s.LastSeenAt, &s.AbsoluteExpiresAt, &s.RevokedAt, &s.CSRFSecret,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AdminSession{}, false, nil
	}
	if err != nil {
		return AdminSession{}, false, fmt.Errorf("store: looking up admin session: %w", err)
	}
	return s, true, nil
}

func (db *DB) TouchAdminSessionLastSeen(ctx context.Context, id uuid.UUID) error {
	if _, err := db.Pool.Exec(ctx, `UPDATE admin_sessions SET last_seen_at = now() WHERE id = $1`, id); err != nil {
		return fmt.Errorf("store: touching admin session last seen: %w", err)
	}
	return nil
}

func (db *DB) RevokeAdminSession(ctx context.Context, id uuid.UUID) error {
	if _, err := db.Pool.Exec(ctx, `UPDATE admin_sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id); err != nil {
		return fmt.Errorf("store: revoking admin session %s: %w", id, err)
	}
	return nil
}

// RevokeAdminSessionsByIssuerSubject backs the deployment CLI's urgent-
// removal command (spec section 9). Returns how many sessions it revoked.
func (db *DB) RevokeAdminSessionsByIssuerSubject(ctx context.Context, oidcIssuer, oidcSubject string) (int64, error) {
	tag, err := db.Pool.Exec(ctx, `
		UPDATE admin_sessions SET revoked_at = now()
		WHERE oidc_issuer = $1 AND oidc_subject = $2 AND revoked_at IS NULL`, oidcIssuer, oidcSubject)
	if err != nil {
		return 0, fmt.Errorf("store: revoking admin sessions for %s/%s: %w", oidcIssuer, oidcSubject, err)
	}
	return tag.RowsAffected(), nil
}
