package enrollment_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/enrollment"
	"github.com/frid-iks/approve-auth/internal/geoip"
	"github.com/frid-iks/approve-auth/internal/notify"
	"github.com/frid-iks/approve-auth/internal/store"
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
		BootstrapPerMinutePerIP:        5,
		StatusPerMinutePerPendingProof: 5,
	}
}

// withGlobalContactInfo sets global_settings.contact_info for the
// duration of one test and restores whatever it was before -- that
// row is a genuine singleton, shared by every test (and the live dev
// stack, if pointed at the same database), so a test that mutates it
// must always put it back.
func withGlobalContactInfo(t *testing.T, db *store.DB, ctx context.Context, contactInfo string) {
	t.Helper()
	original, err := db.GetGlobalSettings(ctx)
	if err != nil {
		t.Fatalf("GetGlobalSettings: %v", err)
	}
	if _, err := db.UpdateGlobalSettings(ctx, original.Version, store.UpdateGlobalSettingsParams{ContactInfo: &contactInfo}, "test"); err != nil {
		t.Fatalf("UpdateGlobalSettings: %v", err)
	}
	t.Cleanup(func() {
		current, err := db.GetGlobalSettings(ctx)
		if err != nil {
			return
		}
		restore := ""
		if original.ContactInfo != nil {
			restore = *original.ContactInfo
		}
		_, _ = db.UpdateGlobalSettings(ctx, current.Version, store.UpdateGlobalSettingsParams{ContactInfo: &restore}, "test")
	})
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
	app, err := db.CreateApplication(ctx, hostname, "Enrollment Test", "", 30*24*time.Hour, 365*24*time.Hour, "", "", "")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	// Most of this file's tests submit a label/message and expect it to
	// be accepted -- AllowAnonymousMessage defaults to false (migration
	// 000020, endpoint-review.md F3), so this shared test application
	// opts in. Tests that specifically exercise the false/default case
	// build their own application instead (see
	// TestSubmitRequest_RejectsMessageWhenNotAllowed).
	allowAnonymousMessage := true
	if _, err := db.UpdateApplication(ctx, app.ID, app.Version, store.UpdateApplicationParams{AllowAnonymousMessage: &allowAnonymousMessage}, "test"); err != nil {
		t.Fatalf("UpdateApplication (enabling AllowAnonymousMessage): %v", err)
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

	return db, enrollment.New(db, geoip.Noop{}, testConfig()), hostname
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

func TestBootstrap_ContactInfoFallsBackToGlobalDefault(t *testing.T) {
	db, svc, hostname := setup(t)
	ctx := context.Background()
	withGlobalContactInfo(t, db, ctx, "global default contact")

	result, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if result.ContactInfo != "global default contact" {
		t.Errorf("ContactInfo = %q, want the global default (this application has no override)", result.ContactInfo)
	}
}

func TestBootstrap_ContactInfoUsesApplicationOverride(t *testing.T) {
	db, svc, _ := setup(t)
	ctx := context.Background()

	hostname := "enrollment-contact-" + randomSuffix(t) + ".example.test"
	app, err := db.CreateApplication(ctx, hostname, "Contact Override Test", "", 30*24*time.Hour, 365*24*time.Hour, "app-specific contact", "", "")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, app.ID) })

	result, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if result.ContactInfo != "app-specific contact" {
		t.Errorf("ContactInfo = %q, want this application's own override, not the global default", result.ContactInfo)
	}
}

func TestBootstrap_UnknownHost(t *testing.T) {
	_, svc, _ := setup(t)
	_, err := svc.Bootstrap(context.Background(), enrollment.BootstrapInput{Hostname: "does-not-exist.example.test"})
	if !errors.Is(err, enrollment.ErrApplicationUnavailable) {
		t.Errorf("Bootstrap: got %v, want ErrApplicationUnavailable", err)
	}
}

// fakeGeoIPLookup is a configurable stand-in for internal/geoip.Lookup,
// so this test doesn't need a real .mmdb file to verify SubmitRequest
// actually persists whatever the lookup resolves.
type fakeGeoIPLookup struct {
	country, city string
	ok            bool
}

func (f fakeGeoIPLookup) Lookup(string) (string, string, bool) {
	return f.country, f.city, f.ok
}

func TestSubmitRequest_EnrichesWithGeoIP(t *testing.T) {
	db, _, hostname := setup(t)
	ctx := context.Background()
	svc := enrollment.New(db, fakeGeoIPLookup{country: "Norway", city: "Oslo", ok: true}, testConfig())

	boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	result, err := svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{
		PendingTokenRaw: boot.RawPendingToken,
		CSRFToken:       boot.CSRFToken,
		ClientIP:        "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}

	requestID, err := uuid.Parse(result.RequestID)
	if err != nil {
		t.Fatalf("parsing request id: %v", err)
	}
	stored, found, err := db.GetApprovalRequestByID(ctx, requestID)
	if err != nil || !found {
		t.Fatalf("GetApprovalRequestByID: found=%v err=%v", found, err)
	}
	if stored.SourceGeoCountry == nil || *stored.SourceGeoCountry != "Norway" {
		t.Errorf("SourceGeoCountry = %v, want \"Norway\"", stored.SourceGeoCountry)
	}
	if stored.SourceGeoCity == nil || *stored.SourceGeoCity != "Oslo" {
		t.Errorf("SourceGeoCity = %v, want \"Oslo\"", stored.SourceGeoCity)
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

func TestSubmitRequest_EnqueuesRequestCreatedNotification(t *testing.T) {
	db, svc, hostname := setup(t)
	ctx := context.Background()

	boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	submitted, err := svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{
		PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken, Label: "Lobby TV", ClientIP: "203.0.113.20",
	})
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}

	pending, err := db.ListPendingNotifications(ctx, 100)
	if err != nil {
		t.Fatalf("ListPendingNotifications: %v", err)
	}
	var found bool
	for _, p := range pending {
		var decoded struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(p.Payload, &decoded); err == nil && decoded.RequestID == submitted.RequestID {
			found = true
			// endpoint-review.md F3: the requester's own label/message
			// must never ride along in the enqueued notification payload.
			if strings.Contains(string(p.Payload), "Lobby TV") {
				t.Errorf("notification payload must not contain the request's label/message: %s", p.Payload)
			}
			if p.EventType != notify.EventRequestCreated {
				t.Errorf("event_type = %q, want %q", p.EventType, notify.EventRequestCreated)
			}
		}
	}
	if !found {
		t.Errorf("no pending notification found for request %s", submitted.RequestID)
	}
}

// TestSubmitRequest_RejectsMessageWhenNotAllowed covers
// endpoint-review.md F3's default-deny: a freshly registered
// application (AllowAnonymousMessage defaults to false) must reject a
// non-empty label/message outright, not silently drop it.
func TestSubmitRequest_RejectsMessageWhenNotAllowed(t *testing.T) {
	db, err := store.Open(context.Background(), skipIfNoDB(t))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(db.Close)
	ctx := context.Background()

	hostname := "enrollment-test-noanon-" + randomSuffix(t) + ".example.test"
	app, err := db.CreateApplication(ctx, hostname, "No Anonymous Messages", "", 30*24*time.Hour, 365*24*time.Hour, "", "", "")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(ctx, `DELETE FROM enrollment_contexts WHERE application_id = $1`, app.ID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, app.ID)
	})
	if app.AllowAnonymousMessage {
		t.Fatalf("newly created application: AllowAnonymousMessage = true, want false by default")
	}

	svc := enrollment.New(db, geoip.Noop{}, testConfig())
	boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if _, err := svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{
		PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken, Message: "please let me in", ClientIP: "203.0.113.55",
	}); !errors.Is(err, enrollment.ErrAnonymousMessageNotAllowed) {
		t.Errorf("SubmitRequest with a message: got %v, want ErrAnonymousMessageNotAllowed", err)
	}

	if _, err := svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{
		PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken, Label: "front-desk-tv", ClientIP: "203.0.113.55",
	}); !errors.Is(err, enrollment.ErrAnonymousMessageNotAllowed) {
		t.Errorf("SubmitRequest with a label: got %v, want ErrAnonymousMessageNotAllowed", err)
	}

	if _, err := svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{
		PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken, ClientIP: "203.0.113.55",
	}); err != nil {
		t.Errorf("SubmitRequest with neither label nor message: got %v, want no error", err)
	}
}

func TestSubmitRequest_IdempotentResubmissionDoesNotEnqueueASecondNotification(t *testing.T) {
	db, svc, hostname := setup(t)
	ctx := context.Background()

	app, found, err := db.GetApplicationByHostname(ctx, hostname)
	if err != nil || !found {
		t.Fatalf("GetApplicationByHostname: found=%v err=%v", found, err)
	}

	boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	in := enrollment.SubmitRequestInput{PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken, ClientIP: "203.0.113.21"}
	if _, err := svc.SubmitRequest(ctx, in); err != nil {
		t.Fatalf("SubmitRequest (first): %v", err)
	}
	if _, err := svc.SubmitRequest(ctx, in); err != nil {
		t.Fatalf("SubmitRequest (resubmit): %v", err)
	}

	pending, err := db.ListPendingNotifications(ctx, 200)
	if err != nil {
		t.Fatalf("ListPendingNotifications: %v", err)
	}
	count := 0
	for _, p := range pending {
		if p.ApplicationID == app.ID {
			count++
		}
	}
	if count != 1 {
		t.Errorf("found %d pending notifications for this application after an idempotent resubmit, want exactly 1", count)
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

// TestSubmitRequest_GlobalRateLimited covers endpoint-review.md F2:
// GlobalEnrollmentPerHour was configured but never consumed. Each
// iteration uses a distinct client IP so the per-app/IP bucket (raised
// well above the loop count here) never trips -- only the shared global
// bucket should.
func TestSubmitRequest_GlobalRateLimited(t *testing.T) {
	db, _, hostname := setup(t)
	ctx := context.Background()

	cfg := testConfig()
	cfg.PendingRequestsPerHourPerAppIP = 1000
	cfg.GlobalEnrollmentPerHour = 2
	svc := enrollment.New(db, geoip.Noop{}, cfg)

	var lastErr error
	for i := 0; i < 5; i++ {
		boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
		if err != nil {
			t.Fatalf("Bootstrap: %v", err)
		}
		_, lastErr = svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{
			PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken,
			ClientIP: fmt.Sprintf("203.0.113.%d", 150+i),
		})
	}
	if !errors.Is(lastErr, enrollment.ErrRateLimited) {
		t.Errorf("submissions across distinct IPs: got %v, want ErrRateLimited from the global bucket", lastErr)
	}
}

func TestBootstrap_RateLimitedPerIP(t *testing.T) {
	_, svc, hostname := setup(t)
	ctx := context.Background()

	var lastErr error
	for i := 0; i < 6; i++ {
		_, lastErr = svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname, ClientIP: "203.0.113.88"})
	}
	if !errors.Is(lastErr, enrollment.ErrRateLimited) {
		t.Errorf("6th bootstrap from the same IP: got %v, want ErrRateLimited", lastErr)
	}

	// A different IP is a separate bucket.
	if _, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname, ClientIP: "203.0.113.89"}); err != nil {
		t.Errorf("bootstrap from a different IP: got %v, want no error", err)
	}
}

func TestStatus_RateLimitedPerPendingProof(t *testing.T) {
	_, svc, hostname := setup(t)
	ctx := context.Background()

	submitAndBootstrap := func() enrollment.BootstrapResult {
		boot, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
		if err != nil {
			t.Fatalf("Bootstrap: %v", err)
		}
		if _, err := svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{PendingTokenRaw: boot.RawPendingToken, CSRFToken: boot.CSRFToken}); err != nil {
			t.Fatalf("SubmitRequest: %v", err)
		}
		return boot
	}

	boot := submitAndBootstrap()
	var lastErr error
	for i := 0; i < 6; i++ {
		_, lastErr = svc.Status(ctx, boot.RawPendingToken)
	}
	if !errors.Is(lastErr, enrollment.ErrRateLimited) {
		t.Errorf("6th status poll for the same pending proof: got %v, want ErrRateLimited", lastErr)
	}

	// A different pending proof is a separate bucket.
	boot2 := submitAndBootstrap()
	if _, err := svc.Status(ctx, boot2.RawPendingToken); err != nil {
		t.Errorf("status for a different pending proof: got %v, want no error", err)
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
	if _, err := db.ApproveRequest(ctx, req.ID, req.Version, time.Now().Add(30*24*time.Hour), 30*time.Minute, "my-tv", "", "admin@example.test", nil, nil, nil); err != nil {
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
	if _, err := db.ApproveRequest(ctx, req.ID, req.Version, time.Now().Add(30*24*time.Hour), 30*time.Minute, "", "", "admin@example.test", nil, nil, nil); err != nil {
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
	if _, err := db.ApproveRequest(ctx, req.ID, req.Version, time.Now().Add(30*24*time.Hour), 30*time.Minute, "", "", "admin@example.test", nil, nil, nil); err != nil {
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
	auth, err := db.ApproveRequest(ctx, req.ID, req.Version, time.Now().Add(30*24*time.Hour), 30*time.Minute, "", "", "admin@example.test", nil, nil, nil)
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

// TestBootstrap_AfterCancel_AllowsFreshRequest covers a real bug found
// in manual testing: a browser cancels its pending request, then
// submits a new manual request with a message -- and lands right back
// on "Request canceled" instead of a fresh pending one. The browser's
// pending cookie is still the same one throughout (Cancel never told it
// otherwise), so unless Cancel also consumes the enrollment context,
// Bootstrap keeps reusing the now-dead context and the new submission
// collides with the canceled row's still-unique pending_token_hash.
func TestBootstrap_AfterCancel_AllowsFreshRequest(t *testing.T) {
	_, svc, hostname := setup(t)
	ctx := context.Background()

	boot1, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname})
	if err != nil {
		t.Fatalf("Bootstrap #1: %v", err)
	}
	req1, err := svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{PendingTokenRaw: boot1.RawPendingToken, CSRFToken: boot1.CSRFToken})
	if err != nil {
		t.Fatalf("SubmitRequest #1: %v", err)
	}
	if err := svc.Cancel(ctx, boot1.RawPendingToken, boot1.CSRFToken); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	// The browser still carries its old pending cookie on its next visit.
	boot2, err := svc.Bootstrap(ctx, enrollment.BootstrapInput{Hostname: hostname, ExistingPendingToken: boot1.RawPendingToken})
	if err != nil {
		t.Fatalf("Bootstrap #2: %v", err)
	}
	if boot2.RawPendingToken == "" || boot2.RawPendingToken == boot1.RawPendingToken {
		t.Fatalf("expected a fresh pending token after cancel, got %q (reused the canceled context)", boot2.RawPendingToken)
	}

	req2, err := svc.SubmitRequest(ctx, enrollment.SubmitRequestInput{
		PendingTokenRaw: boot2.RawPendingToken, CSRFToken: boot2.CSRFToken, Message: "please approve, this is the lobby TV",
	})
	if err != nil {
		t.Fatalf("SubmitRequest #2: %v", err)
	}
	if req2.RequestID == req1.RequestID {
		t.Fatal("expected a new request after cancel + resubmit, got the same canceled request back")
	}

	status, err := svc.Status(ctx, boot2.RawPendingToken)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.State != "pending" {
		t.Errorf("state = %q, want pending (the fresh request, not the canceled one)", status.State)
	}
	if status.VerificationCode != req2.VerificationCode {
		t.Errorf("verification code = %q, want the new request's code %q", status.VerificationCode, req2.VerificationCode)
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
