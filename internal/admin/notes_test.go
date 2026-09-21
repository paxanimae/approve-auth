package admin_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/paxanimae/approve-auth/internal/admin"
)

func TestAddRequestNote_Success(t *testing.T) {
	_, svc, req := setup(t)
	ctx := context.Background()

	note, err := svc.AddRequestNote(ctx, admin.AddRequestNoteInput{RequestID: req.ID.String(), Body: "  a note  ", AuthorBy: "admin@example.test"})
	if err != nil {
		t.Fatalf("AddRequestNote: %v", err)
	}
	if note.Body != "a note" {
		t.Errorf("Body = %q, want trimmed \"a note\"", note.Body)
	}
	if note.AuthorSubject != "admin@example.test" {
		t.Errorf("AuthorSubject = %q, want admin@example.test", note.AuthorSubject)
	}
}

func TestAddRequestNote_RejectsEmptyBody(t *testing.T) {
	_, svc, req := setup(t)
	ctx := context.Background()

	_, err := svc.AddRequestNote(ctx, admin.AddRequestNoteInput{RequestID: req.ID.String(), Body: "   ", AuthorBy: "admin@example.test"})
	if !errors.Is(err, admin.ErrInvalidNote) {
		t.Errorf("AddRequestNote with a blank body: got %v, want ErrInvalidNote", err)
	}
}

func TestAddRequestNote_RejectsBodyOverMaxLength(t *testing.T) {
	_, svc, req := setup(t)
	ctx := context.Background()

	_, err := svc.AddRequestNote(ctx, admin.AddRequestNoteInput{RequestID: req.ID.String(), Body: strings.Repeat("x", 2001), AuthorBy: "admin@example.test"})
	if !errors.Is(err, admin.ErrInvalidNote) {
		t.Errorf("AddRequestNote with a 2001-character body: got %v, want ErrInvalidNote", err)
	}
}

func TestAddRequestNote_UnknownRequestIsNotFound(t *testing.T) {
	_, svc, _ := setup(t)
	ctx := context.Background()

	_, err := svc.AddRequestNote(ctx, admin.AddRequestNoteInput{RequestID: uuid.New().String(), Body: "a note", AuthorBy: "admin@example.test"})
	if !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("AddRequestNote for an unknown request id: got %v, want ErrNotFound", err)
	}
}

func TestAddAuthorizationNote_Success(t *testing.T) {
	_, svc, req := setup(t)
	ctx := context.Background()

	approved, err := svc.Approve(ctx, admin.ApproveInput{RequestID: req.ID.String(), ExpectedVersion: req.Version, ApprovedBy: "admin@example.test"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	note, err := svc.AddAuthorizationNote(ctx, admin.AddAuthorizationNoteInput{AuthorizationID: approved.AuthorizationID, Body: "a session note", AuthorBy: "admin@example.test"})
	if err != nil {
		t.Fatalf("AddAuthorizationNote: %v", err)
	}
	if note.Body != "a session note" {
		t.Errorf("Body = %q, want \"a session note\"", note.Body)
	}
}

func TestAddAuthorizationNote_UnknownAuthorizationIsNotFound(t *testing.T) {
	_, svc, _ := setup(t)
	ctx := context.Background()

	_, err := svc.AddAuthorizationNote(ctx, admin.AddAuthorizationNoteInput{AuthorizationID: uuid.New().String(), Body: "a note", AuthorBy: "admin@example.test"})
	if !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("AddAuthorizationNote for an unknown authorization id: got %v, want ErrNotFound", err)
	}
}
