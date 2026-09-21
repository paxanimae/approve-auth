package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// CreateRequestNote appends an admin's note to a request (never
// editable/deletable afterward -- see migration 000013) and records an
// audit event in the same transaction, matching every other admin
// mutation in this package. A request_id that doesn't exist surfaces as
// the request_notes_request_id_fkey foreign-key violation, for the
// caller to map to "not found" the same way internal/admin already maps
// other constraint violations.
func (db *DB) CreateRequestNote(ctx context.Context, requestID uuid.UUID, authorSubject, body string) (RequestNote, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return RequestNote{}, fmt.Errorf("store: creating request note: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var n RequestNote
	var applicationID uuid.UUID
	err = tx.QueryRow(ctx, `
		WITH note AS (
			INSERT INTO request_notes (request_id, author_subject, body)
			VALUES ($1, $2, $3)
			RETURNING id, request_id, author_subject, body, created_at
		)
		SELECT note.id, note.request_id, note.author_subject, note.body, note.created_at, r.application_id
		FROM note JOIN approval_requests r ON r.id = note.request_id`,
		requestID, authorSubject, body,
	).Scan(&n.ID, &n.RequestID, &n.AuthorSubject, &n.Body, &n.CreatedAt, &applicationID)
	if err != nil {
		return RequestNote{}, fmt.Errorf("store: creating request note: %w", err)
	}

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: authorSubject, Action: "request.note_added",
		ApplicationID: &applicationID, RequestID: &requestID,
	}); err != nil {
		return RequestNote{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return RequestNote{}, fmt.Errorf("store: creating request note: commit: %w", err)
	}
	return n, nil
}

// ListRequestNotes returns a request's notes oldest first (reading
// order for a running commentary).
func (db *DB) ListRequestNotes(ctx context.Context, requestID uuid.UUID) ([]RequestNote, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, request_id, author_subject, body, created_at
		FROM request_notes WHERE request_id = $1 ORDER BY created_at ASC, id ASC`, requestID)
	if err != nil {
		return nil, fmt.Errorf("store: listing request notes: %w", err)
	}
	defer rows.Close()

	var out []RequestNote
	for rows.Next() {
		var n RequestNote
		if err := rows.Scan(&n.ID, &n.RequestID, &n.AuthorSubject, &n.Body, &n.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scanning request note: %w", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing request notes: %w", err)
	}
	return out, nil
}

// CreateAuthorizationNote is CreateRequestNote's exact counterpart for
// an authorization (session) instead of a request.
func (db *DB) CreateAuthorizationNote(ctx context.Context, authorizationID uuid.UUID, authorSubject, body string) (AuthorizationNote, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return AuthorizationNote{}, fmt.Errorf("store: creating authorization note: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var n AuthorizationNote
	var applicationID uuid.UUID
	err = tx.QueryRow(ctx, `
		WITH note AS (
			INSERT INTO authorization_notes (authorization_id, author_subject, body)
			VALUES ($1, $2, $3)
			RETURNING id, authorization_id, author_subject, body, created_at
		)
		SELECT note.id, note.authorization_id, note.author_subject, note.body, note.created_at, auth.application_id
		FROM note JOIN authorizations auth ON auth.id = note.authorization_id`,
		authorizationID, authorSubject, body,
	).Scan(&n.ID, &n.AuthorizationID, &n.AuthorSubject, &n.Body, &n.CreatedAt, &applicationID)
	if err != nil {
		return AuthorizationNote{}, fmt.Errorf("store: creating authorization note: %w", err)
	}

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: authorSubject, Action: "authorization.note_added",
		ApplicationID: &applicationID, AuthorizationID: &authorizationID,
	}); err != nil {
		return AuthorizationNote{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return AuthorizationNote{}, fmt.Errorf("store: creating authorization note: commit: %w", err)
	}
	return n, nil
}

// ListAuthorizationNotes is ListRequestNotes' exact counterpart for an
// authorization (session) instead of a request.
func (db *DB) ListAuthorizationNotes(ctx context.Context, authorizationID uuid.UUID) ([]AuthorizationNote, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, authorization_id, author_subject, body, created_at
		FROM authorization_notes WHERE authorization_id = $1 ORDER BY created_at ASC, id ASC`, authorizationID)
	if err != nil {
		return nil, fmt.Errorf("store: listing authorization notes: %w", err)
	}
	defer rows.Close()

	var out []AuthorizationNote
	for rows.Next() {
		var n AuthorizationNote
		if err := rows.Scan(&n.ID, &n.AuthorizationID, &n.AuthorSubject, &n.Body, &n.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scanning authorization note: %w", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing authorization notes: %w", err)
	}
	return out, nil
}
