// Package integration_test exercises the actual Traefik + approve-auth
// + backend stack from deploy/dev/docker-compose.yml -- mock-only tests
// are insufficient for cookie scope and routing (spec section 16).
//
// Requires (see docs/dev-environment.md):
//
//	docker compose -f deploy/dev/docker-compose.yml up -d --build \
//	  migrate approve-auth backend-protected traefik
//
// and TRAEFIK_ADDR + TEST_DATABASE_URL set, e.g.:
//
//	TRAEFIK_ADDR=127.0.0.1:18443 \
//	TEST_DATABASE_URL=postgres://postgres:devpassword@localhost:5432/approve_auth?sslmode=disable \
//	go test ./tests/integration/...
package integration_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/frid-iks/approve-auth/internal/store"
)

const protectedHostname = "protected.localtest.me"

func skipIfNoStack(t *testing.T) (traefikAddr, dbURL string) {
	t.Helper()
	traefikAddr = os.Getenv("TRAEFIK_ADDR")
	dbURL = os.Getenv("TEST_DATABASE_URL")
	if traefikAddr == "" || dbURL == "" {
		t.Skip("TRAEFIK_ADDR and TEST_DATABASE_URL must both be set; see docs/dev-environment.md")
	}
	return
}

// newTraefikClient dials traefikAddr directly regardless of what host the
// request URL names (equivalent to curl --resolve): the test always
// builds URLs against protectedHostname with no port, so the Host header
// and TLS SNI stay clean, while the actual TCP connection goes wherever
// the dev stack's Traefik entry point actually is.
func newTraefikClient(traefikAddr string) *http.Client {
	dialer := &net.Dialer{}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, traefikAddr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func protectedURL(path string) string {
	return "https://" + protectedHostname + path
}

// seededCredential registers protectedHostname (cleaning it up, and
// everything chained off it, when the test ends) and seeds a fully valid
// authorization + credential directly via SQL -- there is no real
// enrollment/claim flow yet (Milestone 3), so this mirrors what it will
// eventually produce. Returns the raw token to present as the access
// cookie value, and the authorization's id for tests that mutate it
// (e.g. revoking) mid-test.
func seededCredential(t *testing.T, ctx context.Context, dbURL string) (rawToken string, authorizationID string) {
	t.Helper()

	db, err := store.Open(ctx, dbURL)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(db.Close)

	app, err := db.CreateApplication(ctx, protectedHostname, "Integration Test Backend", "", 30*24*time.Hour, 365*24*time.Hour, "", "", "")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}

	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })

	requestTokenHash := sha256.Sum256([]byte(t.Name() + ":request"))
	var requestID string
	err = conn.QueryRow(ctx, `
		INSERT INTO approval_requests (application_id, pending_token_hash, verification_code, deadline_at)
		VALUES ($1, $2, $3, now() + interval '1 hour')
		RETURNING id`, app.ID, requestTokenHash[:], "ITEST-"+t.Name()).Scan(&requestID)
	if err != nil {
		t.Fatalf("inserting approval_request: %v", err)
	}

	err = conn.QueryRow(ctx, `
		INSERT INTO authorizations (application_id, request_id, approved_by, activated_at, expires_at)
		VALUES ($1, $2, 'integration-test', now(), now() + interval '30 days')
		RETURNING id`, app.ID, requestID).Scan(&authorizationID)
	if err != nil {
		t.Fatalf("inserting authorization: %v", err)
	}

	rawToken = "itest-" + t.Name() + "-token"
	credentialTokenHash := sha256.Sum256([]byte(rawToken))
	_, err = conn.Exec(ctx, `
		INSERT INTO credentials (authorization_id, application_id, token_hash, absolute_expires_at)
		VALUES ($1, $2, $3, now() + interval '365 days')`, authorizationID, app.ID, credentialTokenHash[:])
	if err != nil {
		t.Fatalf("inserting credential: %v", err)
	}

	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, `DELETE FROM credentials WHERE authorization_id = $1`, authorizationID)
		_, _ = conn.Exec(ctx, `DELETE FROM authorizations WHERE id = $1`, authorizationID)
		_, _ = conn.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, requestID)
		_, _ = conn.Exec(ctx, `DELETE FROM applications WHERE id = $1`, app.ID)
	})

	return rawToken, authorizationID
}

func TestRealTraefik_MissingCredential_NonNavigation_Unauthorized(t *testing.T) {
	traefikAddr, dbURL := skipIfNoStack(t)
	ctx := context.Background()
	_, _ = seededCredential(t, ctx, dbURL) // registers the host; this request presents no cookie

	client := newTraefikClient(traefikAddr)
	req, err := http.NewRequest(http.MethodGet, protectedURL("/dashboard"), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestRealTraefik_MissingCredential_Navigation_RedirectsToRequestPage(t *testing.T) {
	traefikAddr, dbURL := skipIfNoStack(t)
	ctx := context.Background()
	_, _ = seededCredential(t, ctx, dbURL)

	client := newTraefikClient(traefikAddr)
	req, err := http.NewRequest(http.MethodGet, protectedURL("/dashboard"), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	want := fmt.Sprintf("https://%s/__approve-auth/request?return_to=%%2Fdashboard", protectedHostname)
	if got := resp.Header.Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestRealTraefik_ReservedPathBypassesForwardAuth(t *testing.T) {
	traefikAddr, dbURL := skipIfNoStack(t)
	ctx := context.Background()
	_, _ = seededCredential(t, ctx, dbURL)

	client := newTraefikClient(traefikAddr)
	resp, err := client.Get(protectedURL("/__approve-auth/status"))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// No cookie was presented and the request would otherwise be denied,
	// but the reserved-path router has no approve-auth middleware and
	// goes straight to the Public listener (spec section 6's router
	// topology) -- it must reach the real /status endpoint (200 JSON,
	// "not_requested"), never the 401 the same-cookie-less request would
	// get on the protected router, and never the backend's plain-text
	// content.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (the public listener's real /status, unauthenticated)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (reached approve-auth, not the backend)", ct)
	}
}

func TestRealTraefik_ValidCredential_ReachesBackend(t *testing.T) {
	traefikAddr, dbURL := skipIfNoStack(t)
	ctx := context.Background()
	rawToken, _ := seededCredential(t, ctx, dbURL)

	client := newTraefikClient(traefikAddr)
	req, err := http.NewRequest(http.MethodGet, protectedURL("/dashboard"), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth", Value: rawToken})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if server := resp.Header.Get("Server"); server != "Caddy" {
		t.Errorf("Server = %q, want Caddy (the actual backend, not approve-auth)", server)
	}
}

func TestRealTraefik_RevokedAuthorization_Denied(t *testing.T) {
	traefikAddr, dbURL := skipIfNoStack(t)
	ctx := context.Background()
	rawToken, authorizationID := seededCredential(t, ctx, dbURL)

	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	_, err = conn.Exec(ctx, `UPDATE authorizations SET revoked_at = now(), revoked_by = 'test', revocation_reason = 'test' WHERE id = $1`, authorizationID)
	if err != nil {
		t.Fatalf("revoking: %v", err)
	}

	client := newTraefikClient(traefikAddr)
	req, err := http.NewRequest(http.MethodGet, protectedURL("/dashboard"), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth", Value: rawToken})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// Fail-closed on a total service outage (spec section 6: "Database
// unavailable or decision timeout" -> no backend request) was verified
// manually by stopping the approve-auth container mid-stack and
// confirming Traefik returns 500 rather than proxying to the backend --
// not automated here since it would disrupt this shared dev stack for
// any other test running concurrently against it.
