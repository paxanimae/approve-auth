package enrollment_test

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

	"github.com/frid-iks/traefik-manual-proxy/internal/enrollment"
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

func testConfig() enrollment.Config {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return enrollment.Config{
		RequestTTL:                     24 * time.Hour,
		ClaimTTL:                       30 * time.Minute,
		ClaimRetryTTL:                  10 * time.Minute,
		CredentialMaxAge:               365 * 24 * time.Hour,
		ClaimEncryptionKey:             key,
		ClaimEncryptionKeyID:           "test",
		PendingRequestsPerHourPerAppIP: 5,
	}
}

func setup(t *testing.T) (*store.DB, *enrollment.Service, string) {
	t.Helper()
	dbURL := skipIfNoDB(t)
	ctx := context.Background()

	db, err := store.Open(ctx, dbURL)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(db.Close)

	hostname := "enrollment-test-" + randomSuffix(t) + ".example.test"
	app, err := db.CreateApplication(ctx, hostname, "Enrollment Test", "", 30*24*time.Hour, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	// One sweep covering everything a test creates on top of this
	// application, in dependency order (see internal/admin's test
	// helper, which hit exactly this as a silently-swallowed FK failure
	// when it only cleaned up part of the chain).
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(ctx, `DELETE FROM credentials WHERE application_id = $1`, app.ID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM authorizations WHERE application_id = $1`, app.ID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM approval_requests WHERE application_id = $1`, app.ID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM enrollment_contexts WHERE application_id = $1`, app.ID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, app.ID)
	})

	return db, enrollment.New(db, testConfig()), hostname
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generating suffix: %v", err)
	}
	return hex.EncodeToString(b)
}

func TestBootstrap_CreatesThenReusesContext(t *testing.T) {
	_, svc, hostname := setup(t)
	ctx := context.Background()

	first, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if first.RawPendingToken == "" {
		t.Fatal("expected a new pending token on first bootstrap")
	}

	second, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname, ExistingPendingToken: first.RawPendingToken})
	if err != nil {
		t.Fatalf("Bootstrap (reuse): %v", err)
	}
	if second.RawPendingToken != "" {
		t.Error("expected no new pending token when reusing a live context")
	}
	if second.CSRFToken != first.CSRFToken {
		t.Error("expected the same CSRF token when reusing a live context")
	}
}

func TestBootstrap_UnknownHost(t *testing.T) {
	_, svc, _ := setup(t)
	_, err := svc.Bootstrap(context.Background(), enrollment.BootstrapInput{Hostname: "does-not-exist.example.test"})
	if !errors.Is(err, enrollment.ErrApplicationUnavailable) {
		t.Errorf("Bootstrap: got %v, want ErrApplicationUnavailable", err)
	}
}

func TestSubmitRequest_RequiresValidCSRF(t *testing.T) {
	_, svc, hostname := setup(t)
	ctx := context.Background()

	boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	_, err = svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{
		PendingTokenRaw: boot.RawPendingToken,
		CSRFToken:       "wrong-token",
	})
	if !errors.Is(err, enrollment.ErrInvalidCSRF) {
		t.Errorf("SubmitRequest with wrong CSRF: got %v, want ErrInvalidCSRF", err)
	}
}

func TestSubmitRequest_IsIdempotentForTheSamePendingProof(t *testing.T) {
	_, svc, hostname := setup(t)
	ctx := context.Background()

	boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	in := enrollment.SubmitRequestInput{PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken, Label: "my-tv", ClientIP: "203.0.113.9"}
	first, err := svc.SubmitRequest(ctx, in)
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}
	second, err := svc.SubmitRequest(ctx, in)
	if err != nil {
		t.Fatalf("SubmitRequest (resubmit): %v", err)
	}
	if first.RequestID != second.RequestID || first.VerificationCode != second.VerificationCode {
		t.Errorf("resubmission did not reuse the existing request: first=%+v second=%+v", first, second)
	}
}

func TestSubmitRequest_RateLimited(t *testing.T) {
	_, svc, hostname := setup(t)
	ctx := context.Background()

	// Each iteration bootstraps a *fresh* pending proof (a real browser
	// retrying wouldn't get a new one, but the rate limit is keyed on
	// application+client IP, not the pending proof, so this exercises
	// exactly that limit without idempotent reuse masking it).
	var lastErr error
	for i := 0; i < 6; i++ {
		boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
		if err != nil {
			t.Fatalf("Bootstrap: %v", err)
		}
		_, lastErr = svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{
			PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken, ClientIP: "203.0.113.77",
		})
	}
	if !errors.Is(lastErr, enrollment.ErrRateLimited) {
		t.Errorf("6th submission from the same IP: got %v, want ErrRateLimited", lastErr)
	}
}

func TestFullLifecycle_RequestApproveClaimRetryAck(t *testing.T) {
	db, svc, hostname := setup(t)
	ctx := context.Background()

	boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	submitted, err := svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{
		PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken, ReturnTo: "/dashboard?tab=1",
	})
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}

	status, err := svc.Status(ctx, boot.RawPendingToken)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != "pending" || status.VerificationCode != submitted.VerificationCode {
		t.Fatalf("unexpected status before approval: %+v", status)
	}

	// Simulate an admin's approval directly via store (internal/admin's
	// own tests cover Approve itself; this test is about enrollment's
	// Claim behavior once approved).
	req, found, err := db.GetApprovalRequestByTokenHash(ctx, hashForTest(boot.RawPendingToken))
	if err != nil || !found {
		t.Fatalf("GetApprovalRequestByTokenHash: found=%v err=%v", found, err)
	}
	if _, err := db.ApproveRequest(ctx, req.ID, req.Version, time.Now().Add(30*24*time.Hour), 30*time.Minute, "my-tv", "", "admin@example.test"); err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}

	claimed, err := svc.Claim(ctx, boot.RawPendingToken, boot.CSRFToken)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if claimed.RawAccessToken == "" {
		t.Fatal("expected a raw access token from Claim")
	}
	if claimed.ReturnTo != "/dashboard?tab=1" {
		t.Errorf("ReturnTo = %q, want %q", claimed.ReturnTo, "/dashboard?tab=1")
	}

	// Retry: same pending proof, must return the identical token, not a
	// fresh one -- and must not create a second credential.
	retried, err := svc.Claim(ctx, boot.RawPendingToken, boot.CSRFToken)
	if err != nil {
		t.Fatalf("Claim (retry): %v", err)
	}
	if retried.RawAccessToken != claimed.RawAccessToken {
		t.Error("retried claim returned a different token than the original")
	}

	returnTo, err := svc.Ack(ctx, boot.RawPendingToken)
	if err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if returnTo != "/dashboard?tab=1" {
		t.Errorf("Ack ReturnTo = %q, want %q", returnTo, "/dashboard?tab=1")
	}

	// After ack, the enrollment context itself is consumed (not just the
	// envelope), so a further claim attempt is rejected at the CSRF-
	// lookup stage -- it can no longer recover the token either way
	// (spec section 5: never expose it via recovery).
	if _, err := svc.Claim(ctx, boot.RawPendingToken, boot.CSRFToken); !errors.Is(err, enrollment.ErrInvalidPendingProof) {
		t.Errorf("Claim after ack: got %v, want ErrInvalidPendingProof", err)
	}
}

func TestClaim_AlreadyClaimedButEnvelopePurged(t *testing.T) {
	db, svc, hostname := setup(t)
	ctx := context.Background()

	boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if _, err := svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken}); err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}
	req, found, err := db.GetApprovalRequestByTokenHash(ctx, hashForTest(boot.RawPendingToken))
	if err != nil || !found {
		t.Fatalf("GetApprovalRequestByTokenHash: found=%v err=%v", found, err)
	}
	if _, err := db.ApproveRequest(ctx, req.ID, req.Version, time.Now().Add(30*24*time.Hour), 30*time.Minute, "", "", "admin@example.test"); err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}
	if _, err := svc.Claim(ctx, boot.RawPendingToken, boot.CSRFToken); err != nil {
		t.Fatalf("Claim: %v", err)
	}

	// Simulate the envelope's 10-minute TTL having passed and been
	// purged, without ever acking -- the enrollment context (bootstrap
	// TTL: 24h) is still live, so this reaches the "already claimed"
	// branch rather than the CSRF-lookup rejection TestFullLifecycle
	// exercises after an actual ack.
	if err := db.DeleteClaimEnvelope(ctx, req.ID); err != nil {
		t.Fatalf("DeleteClaimEnvelope: %v", err)
	}

	if _, err := svc.Claim(ctx, boot.RawPendingToken, boot.CSRFToken); !errors.Is(err, enrollment.ErrAlreadyClaimedNoEnvelope) {
		t.Errorf("Claim with a purged envelope: got %v, want ErrAlreadyClaimedNoEnvelope", err)
	}
}

func TestLogout_RevokesOwnAuthorization(t *testing.T) {
	db, svc, hostname := setup(t)
	ctx := context.Background()

	boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if _, err := svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken}); err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}
	req, found, err := db.GetApprovalRequestByTokenHash(ctx, hashForTest(boot.RawPendingToken))
	if err != nil || !found {
		t.Fatalf("GetApprovalRequestByTokenHash: found=%v err=%v", found, err)
	}
	if _, err := db.ApproveRequest(ctx, req.ID, req.Version, time.Now().Add(30*24*time.Hour), 30*time.Minute, "", "", "admin@example.test"); err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}
	claimed, err := svc.Claim(ctx, boot.RawPendingToken, boot.CSRFToken)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	if err := svc.Logout(ctx, hostname, claimed.RawAccessToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	var authorizationID uuid.UUID
	if err := db.Pool.QueryRow(ctx, `SELECT id FROM authorizations WHERE request_id = $1`, req.ID).Scan(&authorizationID); err != nil {
		t.Fatalf("querying authorization id: %v", err)
	}
	auth, ok, err := db.GetAuthorizationByID(ctx, authorizationID)
	if err != nil || !ok {
		t.Fatalf("GetAuthorizationByID: ok=%v err=%v", ok, err)
	}
	if auth.RevokedAt == nil {
		t.Error("expected the authorization to be revoked after Logout")
	}

	// Logging out again (or with a garbage token) must not error.
	if err := svc.Logout(ctx, hostname, claimed.RawAccessToken); err != nil {
		t.Errorf("Logout (repeat): %v", err)
	}
	if err := svc.Logout(ctx, hostname, "not-a-real-token"); err != nil {
		t.Errorf("Logout (garbage token): %v", err)
	}
}

// TestStatus_IncludesCSRFTokenWhileContextIsLive is a regression test:
// the waiting page's cancel/claim forms are only ever functional if
// Status actually carries a CSRF token forward from the enrollment
// context -- a real-Traefik end-to-end test (tests/integration/
// enrollment_flow_test.go) caught this missing when every layer's own
// mocked/fake-backed unit test had no way to notice.
func TestStatus_IncludesCSRFTokenWhileContextIsLive(t *testing.T) {
	_, svc, hostname := setup(t)
	ctx := context.Background()

	boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if _, err := svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken}); err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}

	status, err := svc.Status(ctx, boot.RawPendingToken)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.CSRFToken == "" {
		t.Fatal("Status.CSRFToken is empty while the enrollment context is still live")
	}
	if status.CSRFToken != boot.CSRFToken {
		t.Errorf("Status.CSRFToken = %q, want it to match Bootstrap's %q (same context)", status.CSRFToken, boot.CSRFToken)
	}
}

func TestCancel_RevokesUnclaimedAuthorization(t *testing.T) {
	db, svc, hostname := setup(t)
	ctx := context.Background()

	boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if _, err := svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken}); err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}

	req, found, err := db.GetApprovalRequestByTokenHash(ctx, hashForTest(boot.RawPendingToken))
	if err != nil || !found {
		t.Fatalf("GetApprovalRequestByTokenHash: found=%v err=%v", found, err)
	}
	auth, err := db.ApproveRequest(ctx, req.ID, req.Version, time.Now().Add(30*24*time.Hour), 30*time.Minute, "", "", "admin@example.test")
	if err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}

	if err := svc.Cancel(ctx, boot.RawPendingToken, boot.CSRFToken); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	afterCancel, ok, err := db.GetAuthorizationByID(ctx, auth.ID)
	if err != nil || !ok {
		t.Fatalf("GetAuthorizationByID: ok=%v err=%v", ok, err)
	}
	if afterCancel.RevokedAt == nil {
		t.Error("expected the unclaimed authorization to be revoked when its request is canceled")
	}
}

// hashForTest mirrors the package-private hashToken so this test can
// look a request up by the same key the service computed internally --
// duplicated rather than exported, since exporting it would widen the
// package's real API for a test-only need.
func hashForTest(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
