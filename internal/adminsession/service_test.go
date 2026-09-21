package adminsession_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/frid-iks/approve-auth/internal/adminsession"
	"github.com/frid-iks/approve-auth/internal/oidc"
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

// fakeOIDCClient implements oidc.Client (== adminsession.OIDCClient) and
// records what it was called with, so tests can drive HandleCallback
// with the exact state/nonce/verifier BeginLogin actually generated.
type fakeOIDCClient struct {
	lastState, lastNonce, lastChallenge string

	exchangeIdentity oidc.Identity
	exchangeErr      error
	lastCode         string
	lastVerifier     string
	lastNonceIn      string
}

func (f *fakeOIDCClient) AuthURL(state, nonce, challenge string) string {
	f.lastState, f.lastNonce, f.lastChallenge = state, nonce, challenge
	return "https://idp.example.test/authorize?state=" + state
}

func (f *fakeOIDCClient) Exchange(_ context.Context, code, verifier, expectedNonce string) (oidc.Identity, error) {
	f.lastCode, f.lastVerifier, f.lastNonceIn = code, verifier, expectedNonce
	return f.exchangeIdentity, f.exchangeErr
}

func testConfig() adminsession.Config {
	key := make([]byte, 32) // AES-256
	for i := range key {
		key[i] = byte(i)
	}
	return adminsession.Config{
		OIDCAdminGroups:    []string{"grp-admins"},
		OIDCViewerGroups:   []string{"grp-viewers"},
		IdleTTL:            30 * time.Minute,
		AbsoluteTTL:        8 * time.Hour,
		TransactionTTL:     10 * time.Minute,
		StateEncryptionKey: key,
	}
}

func setup(t *testing.T) (*store.DB, *fakeOIDCClient, *adminsession.Service) {
	t.Helper()
	dbURL := skipIfNoDB(t)
	ctx := context.Background()

	db, err := store.Open(ctx, dbURL)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(db.Close)

	fake := &fakeOIDCClient{}
	svc := adminsession.New(db, fake, testConfig())
	return db, fake, svc
}

func TestBeginLoginAndCallback_Success(t *testing.T) {
	db, fake, svc := setup(t)
	ctx := context.Background()

	fake.exchangeIdentity = oidc.Identity{Issuer: "https://idp.example.test/", Subject: "user-1", DisplayName: "Ada Admin", Groups: []string{"grp-admins"}}

	result, err := svc.BeginLogin(ctx, "/overview")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if result.RedirectURL == "" {
		t.Fatal("expected a non-empty RedirectURL")
	}
	state := fake.lastState

	rawToken, returnPath, err := svc.HandleCallback(ctx, state, "auth-code-123")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if rawToken == "" {
		t.Fatal("expected a non-empty session token")
	}
	if returnPath != "/overview" {
		t.Errorf("returnPath = %q, want /overview", returnPath)
	}
	if fake.lastCode != "auth-code-123" {
		t.Errorf("Exchange was called with code %q, want auth-code-123", fake.lastCode)
	}
	if fake.lastNonceIn != fake.lastNonce {
		t.Error("Exchange was called with a different nonce than AuthURL generated")
	}

	t.Cleanup(func() {
		_, _ = db.Pool.Exec(ctx, `DELETE FROM admin_sessions WHERE oidc_subject = 'user-1'`)
	})

	info, err := svc.ValidateSession(ctx, rawToken)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if info.Role != "administrator" {
		t.Errorf("Role = %q, want administrator", info.Role)
	}
	if info.DisplayName != "Ada Admin" {
		t.Errorf("DisplayName = %q, want Ada Admin", info.DisplayName)
	}
	if info.CSRFToken == "" {
		t.Error("expected a non-empty CSRFToken")
	}
}

func TestHandleCallback_RejectsUnknownState(t *testing.T) {
	_, _, svc := setup(t)
	ctx := context.Background()

	_, _, err := svc.HandleCallback(ctx, "never-issued-state", "code")
	if !errors.Is(err, adminsession.ErrInvalidState) {
		t.Errorf("got %v, want ErrInvalidState", err)
	}
}

func TestHandleCallback_RejectsStateReplay(t *testing.T) {
	db, fake, svc := setup(t)
	ctx := context.Background()
	fake.exchangeIdentity = oidc.Identity{Issuer: "https://idp.example.test/", Subject: "user-2", Groups: []string{"grp-viewers"}}

	if _, err := svc.BeginLogin(ctx, ""); err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	state := fake.lastState

	if _, _, err := svc.HandleCallback(ctx, state, "code-1"); err != nil {
		t.Fatalf("HandleCallback (first): %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM admin_sessions WHERE oidc_subject = 'user-2'`) })

	if _, _, err := svc.HandleCallback(ctx, state, "code-1"); !errors.Is(err, adminsession.ErrInvalidState) {
		t.Errorf("replayed state: got %v, want ErrInvalidState", err)
	}
}

func TestHandleCallback_NoAccessWhenNotInAnyAllowlistedGroup(t *testing.T) {
	_, fake, svc := setup(t)
	ctx := context.Background()
	fake.exchangeIdentity = oidc.Identity{Issuer: "https://idp.example.test/", Subject: "user-3", Groups: []string{"grp-unrelated"}}

	if _, err := svc.BeginLogin(ctx, ""); err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	_, _, err := svc.HandleCallback(ctx, fake.lastState, "code")
	if !errors.Is(err, adminsession.ErrNoAccess) {
		t.Errorf("got %v, want ErrNoAccess", err)
	}
}

// TestHandleCallback_FallsBackToApplicationOwnerRole covers spec's
// third role: an identity that matches neither allowlisted group is not
// denied outright if they own at least one application (granted via
// internal/store.GrantApplicationOwner, e.g. by an administrator using
// the admin console) -- see internal/adminsession/service.go's
// HandleCallback for why this check is a fallback, not a third
// group-mapping rule alongside mapRole's other two.
func TestHandleCallback_FallsBackToApplicationOwnerRole(t *testing.T) {
	db, fake, svc := setup(t)
	ctx := context.Background()
	fake.exchangeIdentity = oidc.Identity{Issuer: "https://idp.example.test/", Subject: "user-owner-1", Groups: []string{"grp-unrelated"}}

	app, err := db.CreateApplication(ctx, "adminsession-owner-fallback.example.test", "Owner Fallback Test", "", 30*24*time.Hour, 365*24*time.Hour, "")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, app.ID) })
	if err := db.GrantApplicationOwner(ctx, app.ID, "user-owner-1", "admin-1"); err != nil {
		t.Fatalf("GrantApplicationOwner: %v", err)
	}

	if _, err := svc.BeginLogin(ctx, ""); err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	rawToken, _, err := svc.HandleCallback(ctx, fake.lastState, "code")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM admin_sessions WHERE oidc_subject = 'user-owner-1'`) })

	info, err := svc.ValidateSession(ctx, rawToken)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if info.Role != "application_owner" {
		t.Errorf("Role = %q, want application_owner", info.Role)
	}
}

func TestMapRole_AdminTakesPriorityOverViewer(t *testing.T) {
	db, fake, svc := setup(t)
	ctx := context.Background()
	fake.exchangeIdentity = oidc.Identity{Issuer: "https://idp.example.test/", Subject: "user-4", Groups: []string{"grp-admins", "grp-viewers"}}

	if _, err := svc.BeginLogin(ctx, ""); err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	rawToken, _, err := svc.HandleCallback(ctx, fake.lastState, "code")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM admin_sessions WHERE oidc_subject = 'user-4'`) })

	info, err := svc.ValidateSession(ctx, rawToken)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if info.Role != "administrator" {
		t.Errorf("Role = %q, want administrator (priority over viewer)", info.Role)
	}
}

func TestValidateSession_NoSessionForUnknownToken(t *testing.T) {
	_, _, svc := setup(t)
	ctx := context.Background()

	_, err := svc.ValidateSession(ctx, "not-a-real-token")
	if !errors.Is(err, adminsession.ErrNoSession) {
		t.Errorf("got %v, want ErrNoSession", err)
	}
}

func TestLogout_RevokesSession(t *testing.T) {
	db, fake, svc := setup(t)
	ctx := context.Background()
	fake.exchangeIdentity = oidc.Identity{Issuer: "https://idp.example.test/", Subject: "user-5", Groups: []string{"grp-viewers"}}

	if _, err := svc.BeginLogin(ctx, ""); err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	rawToken, _, err := svc.HandleCallback(ctx, fake.lastState, "code")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM admin_sessions WHERE oidc_subject = 'user-5'`) })

	info, err := svc.ValidateSession(ctx, rawToken)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}

	if err := svc.Logout(ctx, rawToken, info.CSRFToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := svc.ValidateSession(ctx, rawToken); !errors.Is(err, adminsession.ErrNoSession) {
		t.Errorf("ValidateSession after logout: got %v, want ErrNoSession", err)
	}

	// Logging out again (or a token that was never valid) must not error.
	if err := svc.Logout(ctx, rawToken, info.CSRFToken); err != nil {
		t.Errorf("Logout (repeat): %v", err)
	}
}

func TestLogout_RejectsInvalidCSRF(t *testing.T) {
	db, fake, svc := setup(t)
	ctx := context.Background()
	fake.exchangeIdentity = oidc.Identity{Issuer: "https://idp.example.test/", Subject: "user-7", Groups: []string{"grp-viewers"}}

	if _, err := svc.BeginLogin(ctx, ""); err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	rawToken, _, err := svc.HandleCallback(ctx, fake.lastState, "code")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM admin_sessions WHERE oidc_subject = 'user-7'`) })

	if err := svc.Logout(ctx, rawToken, "wrong-token"); !errors.Is(err, adminsession.ErrInvalidCSRF) {
		t.Errorf("Logout with wrong CSRF token: got %v, want ErrInvalidCSRF", err)
	}

	// The session must still be alive: an invalid CSRF token must not
	// have logged it out anyway.
	if _, err := svc.ValidateSession(ctx, rawToken); err != nil {
		t.Errorf("ValidateSession after rejected logout: got %v, want a live session", err)
	}
}

func TestValidateSession_IdleTimeout(t *testing.T) {
	db, fake, _ := setup(t)
	ctx := context.Background()
	// A separate Service with a near-zero idle TTL, so this test doesn't
	// need to sleep for the real 30-minute default.
	cfg := testConfig()
	cfg.IdleTTL = 1 * time.Nanosecond
	svc := adminsession.New(db, fake, cfg)
	fake.exchangeIdentity = oidc.Identity{Issuer: "https://idp.example.test/", Subject: "user-6", Groups: []string{"grp-viewers"}}

	if _, err := svc.BeginLogin(ctx, ""); err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	rawToken, _, err := svc.HandleCallback(ctx, fake.lastState, "code")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM admin_sessions WHERE oidc_subject = 'user-6'`) })

	time.Sleep(time.Millisecond)
	if _, err := svc.ValidateSession(ctx, rawToken); !errors.Is(err, adminsession.ErrIdleTimeout) {
		t.Errorf("got %v, want ErrIdleTimeout", err)
	}
}
