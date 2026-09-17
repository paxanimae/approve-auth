package admin_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/traefik-manual-proxy/internal/admin"
	"github.com/frid-iks/traefik-manual-proxy/internal/store"
)

func skipIfNoDB(t *testing.T) string {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	return dbURL
}

func testConfig() admin.Config {
	return admin.Config{
		DefaultAuthorizationDuration: 30 * 24 * time.Hour,
		MaxAuthorizationDuration:     365 * 24 * time.Hour,
		ClaimTTL:                     30 * time.Minute,
	}
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generating suffix: %v", err)
	}
	return hex.EncodeToString(b)
}

// setup creates an application and one pending approval request,
// returning the store handle (for fixture setup the admin.Store
// interface doesn't expose), the service under test, and the pending
// request.
func setup(t *testing.T) (*store.DB, *admin.Service, store.ApprovalRequest) {
	t.Helper()
	dbURL := skipIfNoDB(t)
	ctx := context.Background()

	db, err := store.Open(ctx, dbURL)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(db.Close)

	hostname := "admin-test-" + randomSuffix(t) + ".example.test"
	app, err := db.CreateApplication(ctx, hostname, "Admin Test", "", 30*24*time.Hour, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	// One sweep covering everything a test creates on top of this
	// application (authorizations, credentials), in dependency order --
	// not per-row cleanups, since which child rows exist varies by test
	// (Approve alone vs. Approve+Claim+Renew) and each application is
	// unique to its own test anyway.
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(ctx, `DELETE FROM credentials WHERE application_id = $1`, app.ID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM authorizations WHERE application_id = $1`, app.ID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM approval_requests WHERE application_id = $1`, app.ID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, app.ID)
	})

	hash := sha256.Sum256([]byte(t.Name()))
	req, err := db.CreateApprovalRequest(ctx, store.CreateApprovalRequestParams{
		ApplicationID: app.ID, PendingTokenHash: hash[:], VerificationCode: "ADMN-" + randomSuffix(t)[:6], DeadlineAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}

	return db, admin.New(db, testConfig()), req
}

func TestApprove_DefaultExpiry(t *testing.T) {
	_, svc, req := setup(t)
	ctx := context.Background()

	before := time.Now()
	result, err := svc.Approve(ctx, admin.ApproveInput{RequestID: req.ID.String(), ExpectedVersion: req.Version, ApprovedBy: "admin@example.test"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	wantAround := before.Add(30 * 24 * time.Hour)
	if result.ExpiresAt.Before(wantAround.Add(-time.Minute)) || result.ExpiresAt.After(wantAround.Add(time.Minute)) {
		t.Errorf("ExpiresAt = %s, want close to %s (default 30 days)", result.ExpiresAt, wantAround)
	}
}

func TestApprove_RejectsExpiryBeyondMaximum(t *testing.T) {
	_, svc, req := setup(t)
	ctx := context.Background()

	_, err := svc.Approve(ctx, admin.ApproveInput{
		RequestID: req.ID.String(), ExpectedVersion: req.Version, ApprovedBy: "admin@example.test",
		ExpiresAt: time.Now().Add(1000 * 24 * time.Hour),
	})
	if !errors.Is(err, admin.ErrInvalidExpiry) {
		t.Errorf("Approve with expiry beyond the max: got %v, want ErrInvalidExpiry", err)
	}
}

func TestApprove_RejectsExpiryInThePast(t *testing.T) {
	_, svc, req := setup(t)
	ctx := context.Background()

	_, err := svc.Approve(ctx, admin.ApproveInput{
		RequestID: req.ID.String(), ExpectedVersion: req.Version, ApprovedBy: "admin@example.test",
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	if !errors.Is(err, admin.ErrInvalidExpiry) {
		t.Errorf("Approve with a past expiry: got %v, want ErrInvalidExpiry", err)
	}
}

func TestApprove_ConflictOnStaleVersion(t *testing.T) {
	_, svc, req := setup(t)
	ctx := context.Background()

	if _, err := svc.Approve(ctx, admin.ApproveInput{RequestID: req.ID.String(), ExpectedVersion: req.Version, ApprovedBy: "admin@example.test"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := svc.Approve(ctx, admin.ApproveInput{RequestID: req.ID.String(), ExpectedVersion: req.Version, ApprovedBy: "admin@example.test"}); !errors.Is(err, admin.ErrConflict) {
		t.Errorf("re-approving with a stale version: got %v, want ErrConflict", err)
	}
}

func TestDeny_Success(t *testing.T) {
	db, svc, req := setup(t)
	ctx := context.Background()

	if err := svc.Deny(ctx, admin.DenyInput{RequestID: req.ID.String(), ExpectedVersion: req.Version, Reason: "policy", DeniedBy: "admin@example.test"}); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	after, ok, err := db.GetApprovalRequestByTokenHash(ctx, req.PendingTokenHash)
	if err != nil || !ok {
		t.Fatalf("GetApprovalRequestByTokenHash: ok=%v err=%v", ok, err)
	}
	if after.Status != "denied" {
		t.Errorf("Status = %q, want denied", after.Status)
	}
}

func TestDeny_ConflictWhenAlreadyDecided(t *testing.T) {
	_, svc, req := setup(t)
	ctx := context.Background()

	if err := svc.Deny(ctx, admin.DenyInput{RequestID: req.ID.String(), ExpectedVersion: req.Version, DeniedBy: "admin@example.test"}); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if err := svc.Deny(ctx, admin.DenyInput{RequestID: req.ID.String(), ExpectedVersion: req.Version, DeniedBy: "admin@example.test"}); !errors.Is(err, admin.ErrConflict) {
		t.Errorf("denying an already-decided request: got %v, want ErrConflict", err)
	}
}

func TestRevokeAndRenew(t *testing.T) {
	db, svc, req := setup(t)
	ctx := context.Background()

	approved, err := svc.Approve(ctx, admin.ApproveInput{RequestID: req.ID.String(), ExpectedVersion: req.Version, ApprovedBy: "admin@example.test"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Claim directly via store (internal/enrollment owns the real claim
	// flow; renew requires an *activated* authorization).
	rawToken := "admin-test-token-" + t.Name()
	tokenHash := sha256.Sum256([]byte(rawToken))
	if _, _, _, err := db.ClaimApproved(ctx, req.ID, tokenHash[:], 365*24*time.Hour); err != nil {
		t.Fatalf("ClaimApproved: %v", err)
	}

	authID, err := uuid.Parse(approved.AuthorizationID)
	if err != nil {
		t.Fatalf("parsing authorization id: %v", err)
	}
	auth, ok, err := db.GetAuthorizationByID(ctx, authID)
	if err != nil || !ok {
		t.Fatalf("GetAuthorizationByID: ok=%v err=%v", ok, err)
	}

	if err := svc.Renew(ctx, admin.RenewInput{
		AuthorizationID: approved.AuthorizationID, ExpectedVersion: auth.Version,
		NewExpiresAt: auth.ExpiresAt.Add(7 * 24 * time.Hour), RenewedBy: "admin@example.test",
	}); err != nil {
		t.Fatalf("Renew: %v", err)
	}

	renewed, ok, err := db.GetAuthorizationByID(ctx, authID)
	if err != nil || !ok {
		t.Fatalf("GetAuthorizationByID: ok=%v err=%v", ok, err)
	}

	if err := svc.Revoke(ctx, admin.RevokeInput{AuthorizationID: approved.AuthorizationID, ExpectedVersion: renewed.Version, Reason: "done", RevokedBy: "admin@example.test"}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	afterRevoke, ok, err := db.GetAuthorizationByID(ctx, authID)
	if err != nil || !ok {
		t.Fatalf("GetAuthorizationByID: ok=%v err=%v", ok, err)
	}
	if afterRevoke.RevokedAt == nil {
		t.Error("expected RevokedAt to be set")
	}

	if err := svc.Revoke(ctx, admin.RevokeInput{AuthorizationID: approved.AuthorizationID, ExpectedVersion: afterRevoke.Version, Reason: "again", RevokedBy: "admin@example.test"}); !errors.Is(err, admin.ErrConflict) {
		t.Errorf("double revoke: got %v, want ErrConflict", err)
	}
}
