package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestCreateRequestNote_AppendsAndRecordsAudit(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "request-notes.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, "note-code-a")

	n1, err := db.CreateRequestNote(ctx, mustParseUUID(t, reqID), "admin-a", "first note")
	if err != nil {
		t.Fatalf("CreateRequestNote: %v", err)
	}
	if n1.Body != "first note" || n1.AuthorSubject != "admin-a" {
		t.Errorf("unexpected note: %+v", n1)
	}

	if _, err := db.CreateRequestNote(ctx, mustParseUUID(t, reqID), "admin-b", "second note"); err != nil {
		t.Fatalf("CreateRequestNote (second): %v", err)
	}

	notes, err := db.ListRequestNotes(ctx, mustParseUUID(t, reqID))
	if err != nil {
		t.Fatalf("ListRequestNotes: %v", err)
	}
	if len(notes) != 2 || notes[0].Body != "first note" || notes[1].Body != "second note" {
		t.Errorf("ListRequestNotes = %+v, want [first note, second note] oldest first", notes)
	}

	var auditCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'request.note_added' AND request_id = $1`, reqID).Scan(&auditCount); err != nil {
		t.Fatalf("counting audit events: %v", err)
	}
	if auditCount != 2 {
		t.Errorf("audit_events with action=request.note_added for this request = %d, want 2", auditCount)
	}
}

func TestCreateRequestNote_UnknownRequestIsForeignKeyViolation(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	_, err := db.CreateRequestNote(ctx, uuid.New(), "admin-a", "a note")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "request_notes_request_id_fkey" {
		t.Errorf("CreateRequestNote with an unknown request id: err = %v, want a request_notes_request_id_fkey violation", err)
	}
}

func TestCreateAuthorizationNote_AppendsAndRecordsAudit(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "authorization-notes.example.test")
	reqID := insertApprovalRequest(t, ctx, conn, appID, "note-code-b")
	authID := insertAuthorization(t, ctx, conn, appID, reqID, authorizationOpts{ExpiresAt: time.Now().Add(time.Hour)})

	n, err := db.CreateAuthorizationNote(ctx, mustParseUUID(t, authID), "admin-a", "session note")
	if err != nil {
		t.Fatalf("CreateAuthorizationNote: %v", err)
	}
	if n.Body != "session note" {
		t.Errorf("unexpected note: %+v", n)
	}

	notes, err := db.ListAuthorizationNotes(ctx, mustParseUUID(t, authID))
	if err != nil {
		t.Fatalf("ListAuthorizationNotes: %v", err)
	}
	if len(notes) != 1 || notes[0].Body != "session note" {
		t.Errorf("ListAuthorizationNotes = %+v, want exactly one note", notes)
	}

	var auditCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'authorization.note_added' AND authorization_id = $1`, authID).Scan(&auditCount); err != nil {
		t.Fatalf("counting audit events: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("audit_events with action=authorization.note_added for this authorization = %d, want 1", auditCount)
	}
}

func TestCreateAuthorizationNote_UnknownAuthorizationIsForeignKeyViolation(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	_, err := db.CreateAuthorizationNote(ctx, uuid.New(), "admin-a", "a note")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "authorization_notes_authorization_id_fkey" {
		t.Errorf("CreateAuthorizationNote with an unknown authorization id: err = %v, want an authorization_notes_authorization_id_fkey violation", err)
	}
}
