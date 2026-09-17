package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const adminSessionColumns = `id, token_hash, oidc_issuer, oidc_subject, display_name, role, role_snapshot_at, created_at, last_seen_at, absolute_expires_at, revoked_at, csrf_secret`

func scanAdminSession(row scanner) (AdminSession, error) {
	var s AdminSession
	err := row.Scan(
		&s.ID, &s.TokenHash, &s.OIDCIssuer, &s.OIDCSubject, &s.DisplayName, &s.Role,
		&s.RoleSnapshotAt, &s.CreatedAt, &s.LastSeenAt, &s.AbsoluteExpiresAt, &s.RevokedAt, &s.CSRFSecret,
	)
	return s, err
}

// CreateAdminSession persists a freshly logged-in admin session (spec
// section 9). role is a snapshot taken now from the OIDC groups claim --
// spec section 9: "Group changes apply at reauthentication," so this
// isn't re-checked until the next login. Writes an "admin.login_succeeded"
// audit event in the same transaction (spec section 12).
func (db *DB) CreateAdminSession(ctx context.Context, oidcIssuer, oidcSubject, displayName, role string, tokenHash, csrfSecret []byte, absoluteExpiresAt time.Time) (AdminSession, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return AdminSession{}, fmt.Errorf("store: creating admin session: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	s, err := scanAdminSession(tx.QueryRow(ctx, `
		INSERT INTO admin_sessions (token_hash, oidc_issuer, oidc_subject, display_name, role, absolute_expires_at, csrf_secret)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+adminSessionColumns,
		tokenHash, oidcIssuer, oidcSubject, nullableText(displayName), role, absoluteExpiresAt, csrfSecret,
	))
	if err != nil {
		return AdminSession{}, fmt.Errorf("store: creating admin session: %w", err)
	}

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: oidcSubject, Action: "admin.login_succeeded", Reason: role,
	}); err != nil {
		return AdminSession{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return AdminSession{}, fmt.Errorf("store: creating admin session: commit: %w", err)
	}
	return s, nil
}

// RecordAdminLoginFailure audits a login attempt that never reached
// CreateAdminSession -- rejected OIDC state/nonce, a failed code
// exchange, or an authenticated identity with no allowlisted group (spec
// section 12: "admin login success/failure"). actorSubject may be empty
// if the identity itself couldn't be determined.
func (db *DB) RecordAdminLoginFailure(ctx context.Context, actorSubject, reason string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: recording admin login failure: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: actorSubject, Action: "admin.login_failed", Reason: reason, Outcome: "failure",
	}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: recording admin login failure: commit: %w", err)
	}
	return nil
}

// GetLiveAdminSessionByTokenHash checks revocation and the absolute
// expiry only -- idle-timeout is a caller-side check against LastSeenAt
// (spec section 14's ADMIN_IDLE_TTL is config, not schema).
func (db *DB) GetLiveAdminSessionByTokenHash(ctx context.Context, hash []byte) (AdminSession, bool, error) {
	s, err := scanAdminSession(db.Pool.QueryRow(ctx, `
		SELECT `+adminSessionColumns+`
		FROM admin_sessions
		WHERE token_hash = $1 AND revoked_at IS NULL AND absolute_expires_at > now()`, hash))
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

// RevokeAdminSession ends one admin's own session (spec section 9's
// logout). Writes an "admin.logout" audit event in the same transaction;
// revoking an already-revoked session is a no-op with no duplicate event.
func (db *DB) RevokeAdminSession(ctx context.Context, id uuid.UUID) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: revoking admin session %s: begin: %w", id, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var subject string
	err = tx.QueryRow(ctx, `UPDATE admin_sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL RETURNING oidc_subject`, id).Scan(&subject)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: revoking admin session %s: %w", id, err)
	}

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: subject, Action: "admin.logout",
	}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: revoking admin session %s: commit: %w", id, err)
	}
	return nil
}

// RevokeAdminSessionsByIssuerSubject backs the deployment CLI's urgent-
// removal command (spec section 9). Returns how many sessions it revoked,
// and writes one "admin.session_revoked" audit event summarizing the
// bulk action (spec section 12: "bulk operation summaries").
func (db *DB) RevokeAdminSessionsByIssuerSubject(ctx context.Context, oidcIssuer, oidcSubject string) (int64, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: revoking admin sessions for %s/%s: begin: %w", oidcIssuer, oidcSubject, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE admin_sessions SET revoked_at = now()
		WHERE oidc_issuer = $1 AND oidc_subject = $2 AND revoked_at IS NULL`, oidcIssuer, oidcSubject)
	if err != nil {
		return 0, fmt.Errorf("store: revoking admin sessions for %s/%s: %w", oidcIssuer, oidcSubject, err)
	}
	count := tag.RowsAffected()
	if count == 0 {
		return 0, nil
	}

	// ActorType "admin" matches audit_events' CHECK constraint (admin,
	// browser, system) -- this CLI command is itself an administrative
	// action, just issued outside the web console (same precedent as
	// CreateApplication's CLI-issued "application.created" event).
	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: oidcSubject, Action: "admin.session_revoked",
		Reason: fmt.Sprintf("revoked %d session(s) for issuer %s via CLI", count, oidcIssuer),
	}); err != nil {
		return 0, err
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("store: revoking admin sessions for %s/%s: commit: %w", oidcIssuer, oidcSubject, err)
	}
	return count, nil
}
