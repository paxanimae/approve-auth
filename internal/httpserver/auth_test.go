package httpserver_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/frid-iks/traefik-manual-proxy/internal/authz"
	"github.com/frid-iks/traefik-manual-proxy/internal/httpserver"
)

func newAuthRequest(t *testing.T, srvURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srvURL+"/auth", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	// The well-formed baseline every test starts from and mutates.
	req.Header.Set("X-Forwarded-Host", "app.example.test")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Method", "GET")
	req.Header.Set("X-Forwarded-Uri", "/dashboard")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.AddCookie(&http.Cookie{Name: "__Host-manual-proxy", Value: "some-token"})
	return req
}

func doAuth(t *testing.T, decider httpserver.Decider, mutate func(*http.Request)) *http.Response {
	t.Helper()
	mux := httpserver.NewAuthMux(decider, time.Second)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req := newAuthRequest(t, srv.URL)
	if mutate != nil {
		mutate(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("performing request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestAuthHandler_Allow(t *testing.T) {
	resp := doAuth(t, fakeDecider{decision: authz.Decision{Category: authz.CategoryAllow}}, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestAuthHandler_UnknownHost(t *testing.T) {
	resp := doAuth(t, fakeDecider{decision: authz.Decision{Category: authz.CategoryUnknownHost}}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAuthHandler_RevokedOrDisabled(t *testing.T) {
	resp := doAuth(t, fakeDecider{decision: authz.Decision{Category: authz.CategoryRevokedOrDisabled}}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAuthHandler_MissingCredential_Navigation_Redirects(t *testing.T) {
	// The default http.Client follows redirects; disable that so we can
	// inspect the 303 itself.
	mux := httpserver.NewAuthMux(fakeDecider{decision: authz.Decision{Category: authz.CategoryMissingOrInvalidCredential}}, time.Second)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	req := newAuthRequest(t, srv.URL)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("performing request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	want := "https://app.example.test/__manual-approval/request?return_to=%2Fdashboard"
	if location != want {
		t.Errorf("Location = %q, want %q", location, want)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestAuthHandler_MissingCredential_NonNavigation_Unauthorized(t *testing.T) {
	resp := doAuth(t, fakeDecider{decision: authz.Decision{Category: authz.CategoryMissingOrInvalidCredential}}, func(r *http.Request) {
		r.Header.Del("Sec-Fetch-Mode")
		r.Header.Del("Sec-Fetch-Dest")
		r.Header.Set("Accept", "application/json")
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAuthHandler_DeciderError_ServiceUnavailable(t *testing.T) {
	resp := doAuth(t, fakeDecider{err: errors.New("db down")}, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "5" {
		t.Errorf("Retry-After = %q, want %q", got, "5")
	}
}

func TestAuthHandler_MalformedRequest_BadRequest(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"missing X-Forwarded-Host", func(r *http.Request) { r.Header.Del("X-Forwarded-Host") }},
		{"non-https proto", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") }},
		{"missing X-Forwarded-Method", func(r *http.Request) { r.Header.Del("X-Forwarded-Method") }},
		{"missing X-Forwarded-Uri", func(r *http.Request) { r.Header.Del("X-Forwarded-Uri") }},
		{"relative X-Forwarded-Uri", func(r *http.Request) { r.Header.Set("X-Forwarded-Uri", "not-a-path") }},
		{"host contains a slash", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "app.example.test/evil") }},
		{"duplicate access cookie", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Host-manual-proxy", Value: "second-value"})
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := doAuth(t, fakeDecider{decision: authz.Decision{Category: authz.CategoryAllow}}, tt.mutate)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}
