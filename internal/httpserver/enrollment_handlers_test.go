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

	"github.com/frid-iks/approve-auth/internal/authz"
	"github.com/frid-iks/approve-auth/internal/enrollment"
	"github.com/frid-iks/approve-auth/internal/httpserver"
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
	mux := httpserver.NewPublicMux(enroller, decider, time.Hour, 365*24*time.Hour, time.Second, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// recordingEnroller wraps configurableEnroller to capture the ClientIP
// SubmitRequest was actually called with, for asserting on
// endpoint-review.md F2's trusted-proxy client-IP resolution.
type recordingEnroller struct {
	configurableEnroller
	lastClientIP string
}

func (r *recordingEnroller) SubmitRequest(ctx context.Context, in enrollment.SubmitRequestInput) (enrollment.SubmitRequestResult, error) {
	r.lastClientIP = in.ClientIP
	return r.configurableEnroller.SubmitRequest(ctx, in)
}

func submitWithForwardedFor(t *testing.T, srv *httptest.Server, forwardedFor string) {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/requests", strings.NewReader("csrf_token=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+u.Host)
	if forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
}

// TestSubmitRequest_TrustsForwardedForFromTrustedPeer covers
// endpoint-review.md F2: when the immediate TCP peer (httptest binds to
// 127.0.0.1) is inside TrustedTraefikCIDRs, X-Forwarded-For is honored.
func TestSubmitRequest_TrustsForwardedForFromTrustedPeer(t *testing.T) {
	rec := &recordingEnroller{configurableEnroller: configurableEnroller{submitResult: enrollment.SubmitRequestResult{RequestID: "r1", VerificationCode: "AB12-CD34"}}}
	mux := httpserver.NewPublicMux(rec, fakeDecider{}, time.Hour, 365*24*time.Hour, time.Second, []string{"127.0.0.1/32"})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	submitWithForwardedFor(t, srv, "203.0.113.9")

	if rec.lastClientIP != "203.0.113.9" {
		t.Errorf("ClientIP = %q, want the trusted peer's forwarded value %q", rec.lastClientIP, "203.0.113.9")
	}
}

// TestSubmitRequest_IgnoresForwardedForFromUntrustedPeer is F2's other
// half: a direct caller not listed in TrustedTraefikCIDRs cannot forge
// its rate-limit/audit identity via X-Forwarded-For -- the real TCP
// peer address is used instead.
func TestSubmitRequest_IgnoresForwardedForFromUntrustedPeer(t *testing.T) {
	rec := &recordingEnroller{configurableEnroller: configurableEnroller{submitResult: enrollment.SubmitRequestResult{RequestID: "r1", VerificationCode: "AB12-CD34"}}}
	mux := httpserver.NewPublicMux(rec, fakeDecider{}, time.Hour, 365*24*time.Hour, time.Second, []string{"10.0.0.0/8"})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	submitWithForwardedFor(t, srv, "203.0.113.9")

	if rec.lastClientIP == "203.0.113.9" {
		t.Errorf("ClientIP = %q, an untrusted peer's forged X-Forwarded-For must not be trusted", rec.lastClientIP)
	}
	if rec.lastClientIP != "127.0.0.1" {
		t.Errorf("ClientIP = %q, want the real TCP peer address 127.0.0.1", rec.lastClientIP)
	}
}

// TestSubmitRequest_NoTrustedCIDRsIgnoresForwardedFor covers the nil/
// empty TrustedTraefikCIDRs case (e.g. a caller of NewPublicMux that
// hasn't configured any) -- X-Forwarded-For must never be trusted by
// default.
func TestSubmitRequest_NoTrustedCIDRsIgnoresForwardedFor(t *testing.T) {
	rec := &recordingEnroller{configurableEnroller: configurableEnroller{submitResult: enrollment.SubmitRequestResult{RequestID: "r1", VerificationCode: "AB12-CD34"}}}
	srv := newPublicServer(t, rec, fakeDecider{})

	submitWithForwardedFor(t, srv, "203.0.113.9")

	if rec.lastClientIP != "127.0.0.1" {
		t.Errorf("ClientIP = %q, want the real TCP peer address 127.0.0.1 with no trusted CIDRs configured", rec.lastClientIP)
	}
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

	resp, err := http.Get(srv.URL + "/__approve-auth/request")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	cookie := findCookie(resp, "__Host-approve-auth-request")
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

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/__approve-auth/request", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "existing-token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if findCookie(resp, "__Host-approve-auth-request") != nil {
		t.Error("expected no Set-Cookie when reusing an existing live context")
	}
}

func TestSubmitRequest_RejectsBadOrigin(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{submitResult: enrollment.SubmitRequestResult{RequestID: "r1", VerificationCode: "AB12-CD34"}}, fakeDecider{})

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/requests", strings.NewReader("label=tv"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example.test")
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
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

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/requests", strings.NewReader(`{"csrf_token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "null")
	req.Header.Set("Referer", "https://"+u.Host+"/__approve-auth/request")
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
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

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/requests", strings.NewReader(`{"csrf_token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "null")
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
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
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/requests", strings.NewReader(`{"csrf_token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
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
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/requests", strings.NewReader("csrf_token=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/__approve-auth/waiting" {
		t.Errorf("Location = %q, want /__approve-auth/waiting", loc)
	}
}

// TestSubmitRequest_OversizedBodyReturns413 covers endpoint-review.md F1:
// an unauthenticated caller sending an oversized body must be rejected
// with 413 before ever reaching the enrollment service, not merely
// truncated or accepted.
func TestSubmitRequest_OversizedBodyReturns413(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{submitResult: enrollment.SubmitRequestResult{RequestID: "r1", VerificationCode: "AB12-CD34"}}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	oversized := strings.Repeat("a", 64*1024)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/requests", strings.NewReader(`{"message":"`+oversized+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
}

// TestSubmitRequest_OversizedFormBodyReturns413 is the same case via the
// URL-encoded form path, which otherwise falls back to Go's own 10 MiB
// default (endpoint-review.md F1's bounded reproduction).
func TestSubmitRequest_OversizedFormBodyReturns413(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{submitResult: enrollment.SubmitRequestResult{RequestID: "r1", VerificationCode: "AB12-CD34"}}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	oversized := strings.Repeat("a", 64*1024)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/requests", strings.NewReader("message="+oversized))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
}

// TestSubmitRequest_UnsupportedContentTypeReturns415 covers
// endpoint-review.md F1's "accept only the intended content types;
// reject unsupported types explicitly."
func TestSubmitRequest_UnsupportedContentTypeReturns415(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{submitResult: enrollment.SubmitRequestResult{RequestID: "r1", VerificationCode: "AB12-CD34"}}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/requests", strings.NewReader("<xml/>"))
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", resp.StatusCode)
	}
}

// TestSubmitRequest_TrailingJSONDataRejected covers endpoint-review.md
// F1's "validate the complete JSON document, including trailing data."
func TestSubmitRequest_TrailingJSONDataRejected(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{submitResult: enrollment.SubmitRequestResult{RequestID: "r1", VerificationCode: "AB12-CD34"}}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/requests", strings.NewReader(`{"csrf_token":"x"}{"extra":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestClaim_UnsupportedContentTypeReturns415 covers the same content-type
// enforcement on formOrJSONCSRFToken's other two callers (cancel/claim).
func TestClaim_UnsupportedContentTypeReturns415(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/claim", strings.NewReader("csrf_token=x"))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", resp.StatusCode)
	}
}

func TestSubmitRequest_MissingPendingCookie(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/requests", strings.NewReader("csrf_token=x"))
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
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/claim", strings.NewReader("csrf_token=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/__approve-auth/waiting" {
		t.Errorf("Location = %q, want /__approve-auth/waiting (not ReturnTo directly)", loc)
	}
	cookie := findCookie(resp, "__Host-approve-auth")
	if cookie == nil || cookie.Value != "access-token-123" {
		t.Errorf("access cookie = %+v, want value %q", cookie, "access-token-123")
	}
}

func TestAck_RequiresAccessCookie(t *testing.T) {
	srv := newPublicServer(t, configurableEnroller{ackReturnTo: "/dashboard"}, fakeDecider{})

	u, _ := url.Parse(srv.URL)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/ack", nil)
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
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
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/ack", nil)
	req.Header.Set("Origin", "https://"+u.Host)
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth", Value: "access-token"})
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
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/__approve-auth/logout", nil)
	req.Header.Set("Origin", "https://"+u.Host)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	access := findCookie(resp, "__Host-approve-auth")
	pending := findCookie(resp, "__Host-approve-auth-request")
	if access == nil || access.MaxAge >= 0 {
		t.Errorf("access cookie clear = %+v, want MaxAge < 0", access)
	}
	if pending == nil || pending.MaxAge >= 0 {
		t.Errorf("pending cookie clear = %+v, want MaxAge < 0", pending)
	}
}

func TestSession_AllowAndDeny(t *testing.T) {
	allowSrv := newPublicServer(t, configurableEnroller{}, fakeDecider{decision: authz.Decision{Category: authz.CategoryAllow}})
	req, _ := http.NewRequest(http.MethodGet, allowSrv.URL+"/__approve-auth/session", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth", Value: "some-token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("allow case: status = %d, want 200", resp.StatusCode)
	}

	denySrv := newPublicServer(t, configurableEnroller{}, fakeDecider{decision: authz.Decision{Category: authz.CategoryMissingOrInvalidCredential}})
	req2, _ := http.NewRequest(http.MethodGet, denySrv.URL+"/__approve-auth/session", nil)
	req2.AddCookie(&http.Cookie{Name: "__Host-approve-auth", Value: "some-token"})
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
	resp, err := http.Get(srv.URL + "/__approve-auth/session")
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

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/__approve-auth/waiting", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-request", Value: "token"})
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
	if !strings.Contains(body, "/__approve-auth/cancel") {
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
