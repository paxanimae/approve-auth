package integration_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/paxanimae/approve-auth/internal/admin"
	"github.com/paxanimae/approve-auth/internal/store"
)

var csrfTokenPattern = regexp.MustCompile(`name="csrf_token" value="([^"]*)"`)

func extractCSRFToken(t *testing.T, body string) string {
	t.Helper()
	m := csrfTokenPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("could not find csrf_token in page body:\n%s", body)
	}
	return m[1]
}

// newTraefikClientWithJar is newTraefikClient plus a cookie jar, so this
// test can drive the flow the way a real browser would -- letting
// Set-Cookie responses and redirects happen automatically -- instead of
// managing cookies by hand the way the narrower tests in traefik_test.go
// do.
func newTraefikClientWithJar(t *testing.T, traefikAddr string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("creating cookie jar: %v", err)
	}
	dialer := &net.Dialer{}
	return &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, traefikAddr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// postForm submits a form POST the way a real browser would -- Go's
// http.Client.Post doesn't set an Origin header (that's a browser
// behavior, not an HTTP client default), and this service's CSRF
// protection correctly requires one (or a same-origin Referer).
func postForm(t *testing.T, client *http.Client, rawURL, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatalf("building POST request for %s: %v", rawURL, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+protectedHostname)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", rawURL, err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	return string(b)
}

// registerProtectedApplication registers protectedHostname without
// seeding any request/authorization/credential -- unlike
// seededCredential in traefik_test.go, this test drives the real
// enrollment flow itself rather than shortcutting to a pre-claimed
// credential.
func registerProtectedApplication(t *testing.T, ctx context.Context, dbURL string) *store.DB {
	t.Helper()
	db, err := store.Open(ctx, dbURL)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(db.Close)

	app, err := db.CreateApplication(ctx, protectedHostname, "Full Enrollment Flow Test", "", 30*24*time.Hour, 365*24*time.Hour, "", "", "")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(ctx, `DELETE FROM credentials WHERE application_id = $1`, app.ID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM authorizations WHERE application_id = $1`, app.ID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM approval_requests WHERE application_id = $1`, app.ID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM enrollment_contexts WHERE application_id = $1`, app.ID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, app.ID)
	})
	return db
}

// TestRealTraefik_FullEnrollmentFlow drives the entire user journey spec
// section 5 describes -- request, wait, (an admin approving, simulated
// via internal/admin directly since the admin HTTP API isn't wired until
// Milestone 4), claim, and ack -- through the actual running Traefik +
// approve-auth + backend stack, ending with real protected content.
// This is the real version of what tests/integration/traefik_test.go's
// seededCredential shortcuts past.
func TestRealTraefik_FullEnrollmentFlow(t *testing.T) {
	traefikAddr, dbURL := skipIfNoStack(t)
	ctx := context.Background()
	db := registerProtectedApplication(t, ctx, dbURL)
	client := newTraefikClientWithJar(t, traefikAddr)

	// Step 1: GET the request page. A real browser reads the CSRF token
	// out of the rendered form; the pending-proof cookie lands in the
	// jar automatically via Set-Cookie.
	resp, err := client.Get(protectedURL("/__approve-auth/request?return_to=%2Fdashboard"))
	if err != nil {
		t.Fatalf("GET /request: %v", err)
	}
	requestPageBody := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /request: status = %d, body:\n%s", resp.StatusCode, requestPageBody)
	}
	csrfToken := extractCSRFToken(t, requestPageBody)

	// Step 2: submit the request as an HTML form would. The client
	// follows the 303 to /waiting automatically.
	form := "label=integration-test-tv&csrf_token=" + csrfToken + "&return_to=%2Fdashboard"
	resp = postForm(t, client, protectedURL("/__approve-auth/requests"), form)
	waitingBody := readBody(t, resp)
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/__approve-auth/waiting" {
		t.Fatalf("POST /requests: status=%d finalPath=%s body:\n%s", resp.StatusCode, resp.Request.URL.Path, waitingBody)
	}

	// Step 3: poll status like the waiting page's own script would.
	resp, err = client.Get(protectedURL("/__approve-auth/status"))
	if err != nil {
		t.Fatalf("GET /status: %v", err)
	}
	statusBody := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /status: status = %d, body:\n%s", resp.StatusCode, statusBody)
	}

	// Step 4: "an admin approves" -- the admin HTTP API doesn't exist
	// until Milestone 4, so this simulates it the same way an eventual
	// handler would: look up the pending request and call
	// internal/admin.Service directly.
	var requestID string
	var version int32
	if err := db.Pool.QueryRow(ctx, `
		SELECT id, version
		FROM approval_requests WHERE application_id = (SELECT id FROM applications WHERE hostname = $1) AND status = 'pending'
		ORDER BY requested_at DESC LIMIT 1`, protectedHostname).Scan(&requestID, &version); err != nil {
		t.Fatalf("finding the pending request: %v", err)
	}

	adminSvc := admin.New(db, admin.Config{DefaultAuthorizationDuration: 30 * 24 * time.Hour, MaxAuthorizationDuration: 365 * 24 * time.Hour, ClaimTTL: 30 * time.Minute})
	if _, err := adminSvc.Approve(ctx, admin.ApproveInput{RequestID: requestID, ExpectedVersion: version, ApprovedBy: "integration-test-admin"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Step 5: back on the waiting page, the state is now "approved" and
	// offers a claim form with its own CSRF token.
	resp, err = client.Get(protectedURL("/__approve-auth/waiting"))
	if err != nil {
		t.Fatalf("GET /waiting (after approve): %v", err)
	}
	approvedBody := readBody(t, resp)
	claimCSRFToken := extractCSRFToken(t, approvedBody)

	// Step 6: claim. The client follows the 303 back to /waiting; the
	// access cookie lands in the jar via Set-Cookie on that same response.
	resp = postForm(t, client, protectedURL("/__approve-auth/claim"), "csrf_token="+claimCSRFToken)
	claimedWaitingBody := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /claim: status = %d, body:\n%s", resp.StatusCode, claimedWaitingBody)
	}

	// Step 7: the moment of truth -- the real, freshly claimed credential
	// must actually get through ForwardAuth to the real backend.
	resp, err = client.Get(protectedURL("/dashboard"))
	if err != nil {
		t.Fatalf("GET /dashboard (with claimed credential): %v", err)
	}
	dashboardBody := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /dashboard: status = %d, body:\n%s", resp.StatusCode, dashboardBody)
	}
	if server := resp.Header.Get("Server"); server != "Caddy" {
		t.Errorf("GET /dashboard: Server = %q, want Caddy (the real backend, not approve-auth)", server)
	}

	// Step 8: ack, following the spec's step 8 -- it's ack that redirects
	// to the original return_to, not claim.
	resp = postForm(t, client, protectedURL("/__approve-auth/ack"), "")
	ackBody := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /ack: status = %d, body:\n%s", resp.StatusCode, ackBody)
	}
	if resp.Request.URL.Path != "/dashboard" {
		t.Errorf("POST /ack: final path = %s, want /dashboard (the original return_to)", resp.Request.URL.Path)
	}
	if server := resp.Header.Get("Server"); server != "Caddy" {
		t.Errorf("POST /ack final response: Server = %q, want Caddy", server)
	}
}
