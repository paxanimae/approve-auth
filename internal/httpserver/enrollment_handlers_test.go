package httpserver_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/frid-iks/traefik-manual-proxy/internal/authz"
	"github.com/frid-iks/traefik-manual-proxy/internal/enrollment"
	"github.com/frid-iks/traefik-manual-proxy/internal/httpserver"
)

// configurableEnroller lets each test control exactly what the
// "business logic" layer returns, so these tests exercise only the HTTP
// translation (cookies, status codes, content negotiation, origin/CSRF
// gating) -- the real business rules have their own tests against real
// PostgreSQL in internal/enrollment.
type configurableEnroller struct {
	bootstrapResult enrollment.BootstrapResult
	bootstrapErr    error
	submitResult    enrollment.SubmitRequestResult
	submitErr       error
	statusResult    enrollment.StatusResult
	statusErr       error
	cancelErr       error
	claimResult     enrollment.ClaimOutcome
	claimErr        error
	ackReturnTo     string
	ackErr          error
	logoutErr       error
}

func (f configurableEnroller) Bootstrap(context.Context, enrollment.BootstrapInput) (enrollment.BootstrapResult, error) {
	return f.bootstrapResult, f.bootstrapErr
}
func (f configurableEnroller) SubmitRequest(context.Context, enrollment.SubmitRequestInput) (enrollment.SubmitRequestResult, error) {
	return f.submitResult, f.submitErr
}
func (f configurableEnroller) Status(context.Context, string) (enrollment.StatusResult, error) {
	return f.statusResult, f.statusErr
}
func (f configurableEnroller) Cancel(context.Context, string, string) error { return f.cancelErr }
func (f configurableEnroller) Claim(context.Context, string, string) (enrollment.ClaimOutcome, error) {
	return f.claimResult, f.claimErr
}
func (f configurableEnroller) Ack(context.Context, string) (string, error) {
	return f.ackReturnTo, f.ackErr
}
func (f configurableEnroller) Logout(context.Context, string, string) error { return f.logoutErr }

func newPublicServer(t *testing.T, enroller httpserver.Enroller, decider httpserver.Decider) *httptest.Server {
	t.Helper()
	mux := httpserver.NewPublicMux(enroller, decider, time.Hour, 365*24*time.Hour, time.Second)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestRequestPage_SetsNewPendingCookie(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{
		bootstrapResult: enrollment.BootstrapResult{ApplicationDisplayName: "Grafana", ApplicationHostname: "app.example.test", RawPendingToken: "new-raw-token", CSRFToken: "csrf-abc"},
	}, fakeDecider{})

	resp, err := http.Get(srv.URL + "/__manual-approval/request")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	cookie := findCookie(resp, "__Host-manual-request")
	if cookie == nil || cookie.Value != "new-raw-token" {
		t.Errorf("pending cookie = %+v, want value %q", cookie, "new-raw-token")
	}
}

func TestRequestPage_DoesNotResetCookieOnReuse(t *testing.T) {
	// RawPendingToken empty signals "reused an existing live context" --
	// internal/enrollment's own contract.
	srv := newPublicServer(t, configurableEnroller{
		bootstrapResult: enrollment.BootstrapResult{ApplicationDisplayName: "Grafana", ApplicationHostname: "app.example.test", CSRFToken: "csrf-abc"},
	}, fakeDecider{})

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/__manual-approval/request", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-manual-request", Value: "existing-token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if findCookie(resp, "__Host-manual-request") != nil {
		t.Error("expected no Set-Cookie when reusing an existing live context")
	}
}

func TestSubmitRequest_RejectsBadOrigin(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{submitResult: enrollment.SubmitRequestResult{RequestID: "r1", VerificationCode: "AB12-CD34"}}, fakeDecider{})

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__manual-approval/requests", strings.NewReader("label=tv"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example.test")
	req.AddCookie(&http.Cookie{Name: "__Host-manual-request", Value: "token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// TestSubmitRequest_NullOriginFallsBackToReferer covers a real browser
// behavior found in manual testing: some navigation paths (e.g. landing
// on the request page via /auth's own 303 redirect) legitimately produce
// a literal "Origin: null" header rather than omitting Origin entirely.
// That must not be treated as a non-matching Origin outright -- it falls
// back to the same same-origin Referer check an absent Origin would.
func TestSubmitRequest_NullOriginFallsBackToReferer(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{submitResult: enrollment.SubmitRequestResult{RequestID: "r1", VerificationCode: "AB12-CD34"}}, fakeDecider{})
	u, _ := url.Parse(srv.URL)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__manual-approval/requests", strings.NewReader(`{"csrf_token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "null")
	req.Header.Set("Referer", "https://"+u.Host+"/__manual-approval/request")
	req.AddCookie(&http.Cookie{Name: "__Host-manual-request", Value: "token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201 (null Origin + matching Referer must be accepted)", resp.StatusCode)
	}
}

func TestSubmitRequest_NullOriginWithNoRefererIsRejected(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{submitResult: enrollment.SubmitRequestResult{RequestID: "r1", VerificationCode: "AB12-CD34"}}, fakeDecider{})

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__manual-approval/requests", strings.NewReader(`{"csrf_token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "null")
	req.AddCookie(&http.Cookie{Name: "__Host-manual-request", Value: "token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (null Origin with no Referer at all must still be rejected)", resp.StatusCode)
	}
}

func TestSubmitRequest_JSONResponseForJSONCaller(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{submitResult: enrollment.SubmitRequestResult{RequestID: "r1", VerificationCode: "AB12-CD34"}}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__manual-approval/requests", strings.NewReader(`{"csrf_token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-manual-request", Value: "token"})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
}

func TestSubmitRequest_RedirectsToWaitingForFormCaller(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{submitResult: enrollment.SubmitRequestResult{RequestID: "r1", VerificationCode: "AB12-CD34"}}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__manual-approval/requests", strings.NewReader("csrf_token=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-manual-request", Value: "token"})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/__manual-approval/waiting" {
		t.Errorf("Location = %q, want /__manual-approval/waiting", loc)
	}
}

func TestSubmitRequest_MissingPendingCookie(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__manual-approval/requests", strings.NewReader("csrf_token=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+u.Host)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestClaim_SetsAccessCookieAndRedirectsToWaiting(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{claimResult: enrollment.ClaimOutcome{RawAccessToken: "access-token-123", ReturnTo: "/dashboard"}}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__manual-approval/claim", strings.NewReader("csrf_token=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-manual-request", Value: "token"})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/__manual-approval/waiting" {
		t.Errorf("Location = %q, want /__manual-approval/waiting (not ReturnTo directly)", loc)
	}
	cookie := findCookie(resp, "__Host-manual-proxy")
	if cookie == nil || cookie.Value != "access-token-123" {
		t.Errorf("access cookie = %+v, want value %q", cookie, "access-token-123")
	}
}

func TestAck_RequiresAccessCookie(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{ackReturnTo: "/dashboard"}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__manual-approval/ack", nil)
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-manual-request", Value: "token"})
	// deliberately no access cookie
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAck_RedirectsToReturnTo(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{ackReturnTo: "/dashboard?tab=1"}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__manual-approval/ack", nil)
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-manual-request", Value: "token"})
	req.AddCookie(&http.Cookie{Name: "__Host-manual-proxy", Value: "access-token"})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/dashboard?tab=1" {
		t.Errorf("Location = %q, want /dashboard?tab=1", loc)
	}
}

func TestLogout_AlwaysClearsCookies(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__manual-approval/logout", nil)
	req.Header.Set("Origin", "https://"+u.Host)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	access := findCookie(resp, "__Host-manual-proxy")
	pending := findCookie(resp, "__Host-manual-request")
	if access == nil || access.MaxAge >= 0 {
		t.Errorf("access cookie clear = %+v, want MaxAge < 0", access)
	}
	if pending == nil || pending.MaxAge >= 0 {
		t.Errorf("pending cookie clear = %+v, want MaxAge < 0", pending)
	}
}

func TestSession_AllowAndDeny(t *testing.T) {
	allowSrv := newPublicServer(t, configurableEnroller{}, fakeDecider{decision: authz.Decision{Category: authz.CategoryAllow}})
	req, _ := http.NewRequest(http.MethodGet, allowSrv.URL+"/__manual-approval/session", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-manual-proxy", Value: "some-token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("allow case: status = %d, want 200", resp.StatusCode)
	}

	denySrv := newPublicServer(t, configurableEnroller{}, fakeDecider{decision: authz.Decision{Category: authz.CategoryMissingOrInvalidCredential}})
	req2, _ := http.NewRequest(http.MethodGet, denySrv.URL+"/__manual-approval/session", nil)
	req2.AddCookie(&http.Cookie{Name: "__Host-manual-proxy", Value: "some-token"})
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("deny case: status = %d, want 401", resp2.StatusCode)
	}
}

func TestSession_NoCookieIsUnauthorized(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{}, fakeDecider{decision: authz.Decision{Category: authz.CategoryAllow}})
	resp, err := http.Get(srv.URL + "/__manual-approval/session")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestWaitingPage_RendersVerificationCodeWhenPending(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{statusResult: enrollment.StatusResult{State: "pending", VerificationCode: "AB12-CD34"}}, fakeDecider{})

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/__manual-approval/waiting", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-manual-request", Value: "token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, "AB12-CD34") {
		t.Errorf("waiting page body does not contain the verification code:\n%s", body)
	}
	if !strings.Contains(body, "/__manual-approval/cancel") {
		t.Errorf("waiting page body does not contain a cancel form action:\n%s", body)
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	return string(b)
}
