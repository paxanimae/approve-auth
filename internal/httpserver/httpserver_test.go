package httpserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/frid-iks/traefik-manual-proxy/internal/authz"
	"github.com/frid-iks/traefik-manual-proxy/internal/enrollment"
	"github.com/frid-iks/traefik-manual-proxy/internal/httpserver"
)

// fakeDecider lets httpserver tests exercise the /auth response-mapping
// contract without a real authz.Service (and therefore no database)
// underneath it.
type fakeDecider struct {
	decision authz.Decision
	err      error
}

func (f fakeDecider) Decide(_ context.Context, _ authz.AuthRequest) (authz.Decision, error) {
	return f.decision, f.err
}

// fakeEnroller is a minimal stand-in for internal/enrollment.Service, for
// tests that only care about routing/listener separation, not the real
// enrollment business logic (that's internal/enrollment's own tests).
type fakeEnroller struct{}

func (fakeEnroller) Bootstrap(context.Context, enrollment.BootstrapInput) (enrollment.BootstrapResult, error) {
	return enrollment.BootstrapResult{}, enrollment.ErrApplicationUnavailable
}
func (fakeEnroller) SubmitRequest(context.Context, enrollment.SubmitRequestInput) (enrollment.SubmitRequestResult, error) {
	return enrollment.SubmitRequestResult{}, enrollment.ErrInvalidPendingProof
}
func (fakeEnroller) Status(context.Context, string) (enrollment.StatusResult, error) {
	return enrollment.StatusResult{}, enrollment.ErrInvalidPendingProof
}
func (fakeEnroller) Cancel(context.Context, string, string) error {
	return enrollment.ErrInvalidPendingProof
}
func (fakeEnroller) Claim(context.Context, string, string) (enrollment.ClaimOutcome, error) {
	return enrollment.ClaimOutcome{}, enrollment.ErrInvalidPendingProof
}
func (fakeEnroller) Ack(context.Context, string) (string, error) {
	return "", enrollment.ErrInvalidPendingProof
}
func (fakeEnroller) Logout(context.Context, string, string) error {
	return nil
}

type route struct {
	method string
	path   string
}

type listener struct {
	name   string
	mux    *http.ServeMux
	routes []route
}

func listeners() []listener {
	return []listener{
		{
			name: "public",
			mux:  httpserver.NewPublicMux(fakeEnroller{}, fakeDecider{decision: authz.Decision{Category: authz.CategoryAllow}}, time.Hour, time.Hour, time.Second),
			routes: []route{
				{"GET", "/__manual-approval/request"},
				{"POST", "/__manual-approval/requests"},
				{"GET", "/__manual-approval/waiting"},
				{"GET", "/__manual-approval/status"},
				{"POST", "/__manual-approval/cancel"},
				{"POST", "/__manual-approval/claim"},
				{"GET", "/__manual-approval/session"},
				{"POST", "/__manual-approval/ack"},
				{"POST", "/__manual-approval/logout"},
				{"GET", "/__manual-approval/assets/app.js"},
			},
		},
		{
			name: "admin",
			mux:  httpserver.NewAdminMux(fakeAdminSessions{}, fakeAdminActions{}, fakeAdminReadStore{}, "admin.example.test", time.Hour, time.Hour, time.Hour),
			routes: []route{
				{"GET", "/auth/login"},
				{"GET", "/auth/callback"},
				{"POST", "/auth/logout"},
				{"GET", "/api/v1/me"},
				{"GET", "/api/v1/overview"},
				{"GET", "/api/v1/applications"},
				{"POST", "/api/v1/applications"},
				{"GET", "/api/v1/applications/some-id"},
				{"PATCH", "/api/v1/applications/some-id"},
				{"POST", "/api/v1/applications/some-id/disable"},
				{"POST", "/api/v1/applications/some-id/enable"},
				{"GET", "/api/v1/requests"},
				{"GET", "/api/v1/requests/some-id"},
				{"POST", "/api/v1/requests/some-id/approve"},
				{"POST", "/api/v1/requests/some-id/deny"},
				{"GET", "/api/v1/authorizations"},
				{"GET", "/api/v1/authorizations/some-id"},
				{"POST", "/api/v1/authorizations/some-id/renew"},
				{"POST", "/api/v1/authorizations/some-id/revoke"},
				{"POST", "/api/v1/authorizations/bulk-renew"},
				{"POST", "/api/v1/authorizations/bulk-revoke"},
				{"GET", "/api/v1/audit-events"},
				{"GET", "/api/v1/audit-events/export"},
			},
		},
		{
			name: "auth",
			mux:  httpserver.NewAuthMux(fakeDecider{decision: authz.Decision{Category: authz.CategoryAllow}}, time.Second),
			routes: []route{
				{"GET", "/auth"},
			},
		},
		{
			name: "ops",
			mux:  httpserver.NewOpsMux(),
			routes: []route{
				{"GET", "/livez"},
			},
		},
	}
}

func do(t *testing.T, mux *http.ServeMux, r route) int {
	t.Helper()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequest(r.method, srv.URL+r.path, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("performing request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestOwnRoutesAreServed(t *testing.T) {
	for _, l := range listeners() {
		for _, r := range l.routes {
			status := do(t, l.mux, r)
			if status == http.StatusNotFound {
				t.Errorf("%s listener: %s %s: got 404, want it to be routed (even if stubbed)", l.name, r.method, r.path)
			}
		}
	}
}

// TestCrossListenerRoutesAreUnreachable is the exit gate's core assertion:
// every listener is a separate http.ServeMux, so a route that exists on
// one listener must 404 on every other one -- not merely be denied by a
// policy check that a misconfiguration could bypass.
func TestCrossListenerRoutesAreUnreachable(t *testing.T) {
	all := listeners()
	for _, target := range all {
		for _, other := range all {
			if other.name == target.name {
				continue
			}
			for _, r := range other.routes {
				status := do(t, target.mux, r)
				if status != http.StatusNotFound {
					t.Errorf("%s listener: %s %s (belongs to %s listener): got %d, want 404", target.name, r.method, r.path, other.name, status)
				}
			}
		}
	}
}

func TestPublicAssetsServeEmbeddedContent(t *testing.T) {
	mux := httpserver.NewPublicMux(fakeEnroller{}, fakeDecider{}, time.Hour, time.Hour, time.Second)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/__manual-approval/assets/tokens.css")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}

	resp2, err := http.Get(srv.URL + "/__manual-approval/assets/does-not-exist.css")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("got status %d, want 404 for a nonexistent asset", resp2.StatusCode)
	}
}

func TestLivezReturnsOKWithNoStore(t *testing.T) {
	mux := httpserver.NewOpsMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/livez")
	if err != nil {
		t.Fatalf("GET /livez: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /livez: got status %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("GET /livez: Cache-Control = %q, want %q", got, "no-store")
	}
}
