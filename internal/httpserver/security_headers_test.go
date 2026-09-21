package httpserver_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/paxanimae/approve-auth/internal/httpserver"
)

// TestSecurityHeaders_PresentOnBothBrowserFacingListeners covers spec
// section 11, control 4: CSP, Referrer-Policy, and X-Content-Type-Options
// on every response from the Public and Admin listeners -- including an
// outright 404, since the middleware wraps the whole mux rather than
// individual handlers.
func TestSecurityHeaders_PresentOnBothBrowserFacingListeners(t *testing.T) {
	muxes := map[string]*http.ServeMux{
		"public": httpserver.NewPublicMux(fakeEnroller{}, fakeDecider{}, time.Hour, time.Hour, time.Second, nil, ""),
		"admin":  httpserver.NewAdminMux(fakeAdminSessions{}, fakeAdminActions{}, fakeAdminReadStore{}, "admin.example.test", time.Hour, time.Hour, time.Hour, time.Hour, time.Hour, time.Hour, "test", "test"),
	}

	for name, mux := range muxes {
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)

		resp, err := http.Get(srv.URL + "/this-path-does-not-exist")
		if err != nil {
			t.Fatalf("%s: GET: %v", name, err)
		}
		defer func() { _ = resp.Body.Close() }()

		if got := resp.Header.Get("Content-Security-Policy"); got == "" {
			t.Errorf("%s: missing Content-Security-Policy header", name)
		}
		if got := resp.Header.Get("Referrer-Policy"); got != "same-origin" {
			t.Errorf("%s: Referrer-Policy = %q, want same-origin", name, got)
		}
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", name, got)
		}
	}
}
