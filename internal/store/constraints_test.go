package store_test

import (
	"context"
	"testing"
)

func TestConstraints_DuplicateHostnameRejected(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	conn := connectAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	insertApplication(t, ctx, conn, "dup-hostname.example.test")

	_, err := conn.Exec(ctx, `
		INSERT INTO applications (hostname, display_name, default_duration_seconds, max_duration_seconds)
		VALUES ('dup-hostname.example.test', 'Second', 60, 120)`)
	if err == nil {
		t.Fatal("expected a unique violation inserting a duplicate hostname, got nil error")
	}
}

func TestConstraints_UppercaseHostnameRejected(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	conn := connectAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	_, err := conn.Exec(ctx, `
		INSERT INTO applications (hostname, display_name, default_duration_seconds, max_duration_seconds)
		VALUES ('Upper.Example.Test', 'Upper', 60, 120)`)
	if err == nil {
		t.Fatal("expected a check violation inserting an uppercase hostname, got nil error")
	}
}

func TestConstraints_HostnameImmutable(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	conn := connectAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	id := insertApplication(t, ctx, conn, "immutable.example.test")

	_, err := conn.Exec(ctx, `UPDATE applications SET hostname = 'changed.example.test' WHERE id = $1`, id)
	if err == nil {
		t.Fatal("expected the hostname-immutable trigger to reject an UPDATE, got nil error")
	}
}

func TestConstraints_AuthorizationApplicationMismatchRejected(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	conn := connectAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	appA := insertApplication(t, ctx, conn, "app-a.example.test")
	appB := insertApplication(t, ctx, conn, "app-b.example.test")
	requestID := insertApprovalRequest(t, ctx, conn, appA, t.Name())

	// The composite FK (request_id, application_id) -> approval_requests
	// (id, application_id) must reject an authorization that claims a
	// different application than the one its request actually belongs to.
	_, err := conn.Exec(ctx, `
		INSERT INTO authorizations (application_id, request_id, approved_by, expires_at)
		VALUES ($1, $2, 'tester', now() + interval '30 days')`, appB, requestID)
	if err == nil {
		t.Fatal("expected the composite FK to reject a cross-application authorization, got nil error")
	}

	// Sanity check: the matching application_id succeeds.
	_, err = conn.Exec(ctx, `
		INSERT INTO authorizations (application_id, request_id, approved_by, expires_at)
		VALUES ($1, $2, 'tester', now() + interval '30 days')`, appA, requestID)
	if err != nil {
		t.Fatalf("expected the matching-application authorization to succeed, got: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM authorizations WHERE request_id = $1`, requestID) })
}

func TestConstraints_CredentialAuthorizationMismatchRejected(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	conn := connectAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	appA := insertApplication(t, ctx, conn, "cred-app-a.example.test")
	appB := insertApplication(t, ctx, conn, "cred-app-b.example.test")
	requestID := insertApprovalRequest(t, ctx, conn, appA, t.Name())

	var authorizationID string
	err := conn.QueryRow(ctx, `
		INSERT INTO authorizations (application_id, request_id, approved_by, expires_at)
		VALUES ($1, $2, 'tester', now() + interval '30 days')
		RETURNING id`, appA, requestID).Scan(&authorizationID)
	if err != nil {
		t.Fatalf("inserting authorization: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM authorizations WHERE id = $1`, authorizationID) })

	_, err = conn.Exec(ctx, `
		INSERT INTO credentials (authorization_id, application_id, token_hash, absolute_expires_at)
		VALUES ($1, $2, $3, now() + interval '365 days')`, authorizationID, appB, make([]byte, 32))
	if err == nil {
		t.Fatal("expected the composite FK to reject a cross-application credential, got nil error")
	}
}

func TestConstraints_VerificationCodeUniqueAmongLiveRequests(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	conn := connectAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "verification-code.example.test")
	insertApprovalRequest(t, ctx, conn, appID, "SHARED-CODE")

	_, err := conn.Exec(ctx, `
		INSERT INTO approval_requests (application_id, pending_token_hash, verification_code, deadline_at)
		VALUES ($1, $2, 'SHARED-CODE', now() + interval '1 hour')`, appID, make([]byte, 32))
	if err == nil {
		t.Fatal("expected a unique violation for a duplicate live verification code, got nil error")
	}
}
