package httpserver_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/admin"
	"github.com/frid-iks/approve-auth/internal/adminsession"
	"github.com/frid-iks/approve-auth/internal/httpserver"
	"github.com/frid-iks/approve-auth/internal/store"
)

const testAdminHost = "admin.example.test"
const testVersion = "test-version"
const testInstanceName = "test-instance"

func newAdminServer(t *testing.T, sessions httpserver.AdminSessions, actions httpserver.AdminActions, readStore httpserver.AdminReadStore) *httptest.Server {
	t.Helper()
	mux := httpserver.NewAdminMux(sessions, actions, readStore, testAdminHost, time.Hour, 7*24*time.Hour, 24*time.Hour, 30*24*time.Hour, 365*24*time.Hour, time.Hour, testVersion, testInstanceName)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// adminRequest builds a request with the admin Host set (so it passes
// requireAdminHost) and, optionally, a session cookie and CSRF header.
func adminRequest(t *testing.T, method, url, cookieValue, csrfToken string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Host = testAdminHost
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: "__Host-approve-auth-admin", Value: cookieValue})
	}
	if csrfToken != "" {
		req.Header.Set("X-CSRF-Token", csrfToken)
	}
	return req
}

func TestAdminAPI_RejectsWrongHost(t *testing.T) {
	srv := newAdminServer(t, fakeAdminSessions{}, fakeAdminActions{}, fakeAdminReadStore{})
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/me", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	// Host left as the httptest server's own 127.0.0.1 address --
	// intentionally not testAdminHost.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got status %d, want 403 (unknown_host)", resp.StatusCode)
	}
}

func TestAdminAPI_RequiresSessionCookie(t *testing.T) {
	srv := newAdminServer(t, fakeAdminSessions{validateErr: adminsession.ErrNoSession}, fakeAdminActions{}, fakeAdminReadStore{})
	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/me", "", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got status %d, want 401 (no_session)", resp.StatusCode)
	}
}

func TestAdminMe_ReturnsIdentity(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", DisplayName: "Ada Admin", Role: "viewer", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/me", "any-cookie-value", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["subject"] != "user-1" || body["role"] != "viewer" || body["csrf_token"] != "tok-abc" {
		t.Errorf("unexpected /me body: %+v", body)
	}
	// Matches newAdminServer's own (30d, 365d) durations -- the console's
	// approve/renew "permanent" option relies on this being the server's
	// real configured ceiling, not a client-side guess.
	if body["default_authorization_duration_seconds"] != float64(30*24*time.Hour/time.Second) {
		t.Errorf("default_authorization_duration_seconds = %v, want %v", body["default_authorization_duration_seconds"], 30*24*time.Hour/time.Second)
	}
	if body["max_authorization_duration_seconds"] != float64(365*24*time.Hour/time.Second) {
		t.Errorf("max_authorization_duration_seconds = %v, want %v", body["max_authorization_duration_seconds"], 365*24*time.Hour/time.Second)
	}
	if body["version"] != testVersion {
		t.Errorf("version = %v, want %v", body["version"], testVersion)
	}
	if body["instance_name"] != testInstanceName {
		t.Errorf("instance_name = %v, want %v", body["instance_name"], testInstanceName)
	}
}

func TestAdminMutation_ViewerRoleForbidden(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "viewer", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	body := strings.NewReader(`{"version":1,"reason":"test"}`)
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/applications/"+uuid.New().String()+"/disable", "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got status %d, want 403 (administrator role required)", resp.StatusCode)
	}
}

func TestAdminMutation_RequiresMatchingCSRFToken(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "administrator", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	// Missing token.
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/applications/"+uuid.New().String()+"/enable", "any-cookie-value", "", strings.NewReader(`{"version":1}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("missing CSRF token: got status %d, want 403", resp.StatusCode)
	}

	// Wrong token.
	req2 := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/applications/"+uuid.New().String()+"/enable", "any-cookie-value", "wrong-token", strings.NewReader(`{"version":1}`))
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("wrong CSRF token: got status %d, want 403", resp2.StatusCode)
	}

	// Correct token succeeds (fakeAdminActions.EnableApplication defaults to a zero Application, nil error).
	req3 := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/applications/"+uuid.New().String()+"/enable", "any-cookie-value", "tok-abc", strings.NewReader(`{"version":1}`))
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp3.Body.Close() }()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("correct CSRF token: got status %d, want 200", resp3.StatusCode)
	}
}

func TestAdminLogin_RedirectsToProvider(t *testing.T) {
	srv := newAdminServer(t, fakeAdminSessions{beginLoginResult: adminsession.BeginLoginResult{RedirectURL: "https://idp.example.test/authorize?state=xyz"}}, fakeAdminActions{}, fakeAdminReadStore{})

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(adminRequest(t, http.MethodGet, srv.URL+"/auth/login", "", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got status %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://idp.example.test/authorize?state=xyz" {
		t.Errorf("Location = %q, want the IdP authorize URL", got)
	}
}

func TestAdminCallback_SetsSessionCookieAndRedirects(t *testing.T) {
	srv := newAdminServer(t, fakeAdminSessions{callbackToken: "raw-session-token", callbackReturn: "/overview"}, fakeAdminActions{}, fakeAdminReadStore{})

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(adminRequest(t, http.MethodGet, srv.URL+"/auth/callback?state=s&code=c", "", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("got status %d, want 303", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/overview" {
		t.Errorf("Location = %q, want /overview", got)
	}
	cookie := findCookie(resp, "__Host-approve-auth-admin")
	if cookie == nil || cookie.Value != "raw-session-token" {
		t.Errorf("expected __Host-approve-auth-admin cookie set to raw-session-token, got %+v", cookie)
	}
}

func TestAdminCallback_MapsNoAccessError(t *testing.T) {
	srv := newAdminServer(t, fakeAdminSessions{callbackErr: adminsession.ErrNoAccess}, fakeAdminActions{}, fakeAdminReadStore{})

	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/auth/callback?state=s&code=c", "", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got status %d, want 403 (no_access)", resp.StatusCode)
	}
}

func TestAdminLogout_RequiresCSRFThenClearsCookie(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "viewer", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	badReq := adminRequest(t, http.MethodPost, srv.URL+"/auth/logout", "any-cookie-value", "", nil)
	badResp, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = badResp.Body.Close() }()
	if badResp.StatusCode != http.StatusForbidden {
		t.Errorf("logout without CSRF: got status %d, want 403", badResp.StatusCode)
	}

	goodReq := adminRequest(t, http.MethodPost, srv.URL+"/auth/logout", "any-cookie-value", "tok-abc", nil)
	goodResp, err := http.DefaultClient.Do(goodReq)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = goodResp.Body.Close() }()
	if goodResp.StatusCode != http.StatusOK {
		t.Errorf("logout with CSRF: got status %d, want 200", goodResp.StatusCode)
	}
	cookie := findCookie(goodResp, "__Host-approve-auth-admin")
	if cookie == nil || cookie.MaxAge >= 0 {
		t.Errorf("expected __Host-approve-auth-admin to be cleared, got %+v", cookie)
	}
}

func TestCreateApplication_DuplicateHostnameMapsTo409(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "administrator", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{createApplicationErr: admin.ErrDuplicateHostname}, fakeAdminReadStore{})

	body := strings.NewReader(`{"hostname":"dup.example.test","display_name":"Dup"}`)
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/applications", "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("got status %d, want 409 (duplicate_hostname)", resp.StatusCode)
	}
}

func TestCreateApplication_ContactInfoTooLongMapsTo422(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "administrator", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	body := strings.NewReader(`{"hostname":"a.example.test","display_name":"A","contact_info":"` + strings.Repeat("x", 501) + `"}`)
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/applications", "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("got status %d, want 422", resp.StatusCode)
	}
}

func TestCreateApplication_InvalidNotifyWebhookURLMapsTo422(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "administrator", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	body := strings.NewReader(`{"hostname":"a.example.test","display_name":"A","notify_webhook_url":"not-a-url"}`)
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/applications", "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("got status %d, want 422 (notify_webhook_url must be an absolute http(s) URL)", resp.StatusCode)
	}
}

func TestUpdateApplication_InvalidNotifyWebhookURLMapsTo422(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "administrator", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	body := strings.NewReader(`{"version":1,"notify_webhook_url":"ftp://wrong-scheme.example.test"}`)
	req := adminRequest(t, http.MethodPatch, srv.URL+"/api/v1/applications/"+uuid.New().String(), "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PATCH: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("got status %d, want 422 (notify_webhook_url must be an absolute http(s) URL)", resp.StatusCode)
	}
}

func TestGetApplication_ContactInfoOmittedWhenNoOverride(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "viewer", CSRFToken: "tok-abc"}
	appID := uuid.New()
	app := store.Application{ID: appID, ContactInfo: nil}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{application: app, applicationFound: true})

	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/applications/"+appID.String(), "any-cookie-value", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if _, present := body["contact_info"]; present {
		t.Errorf("contact_info present in response (%v) for an application with no override, want it omitted", body["contact_info"])
	}
}

func TestGetRequest_IncludesRequestingApplication(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "viewer", CSRFToken: "tok-abc"}
	reqID := uuid.New()
	req := store.ApprovalRequest{ID: reqID, ApplicationHostname: "app-a.internal", ApplicationDisplayName: "App A"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{request: req, requestFound: true})

	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/requests/"+reqID.String(), "any-cookie-value", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["application_hostname"] != "app-a.internal" || body["application_display_name"] != "App A" {
		t.Errorf("unexpected application fields: %+v", body)
	}
}

func TestGetAuthorization_IncludesRequestingApplication(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "viewer", CSRFToken: "tok-abc"}
	authID := uuid.New()
	auth := store.Authorization{ID: authID, ApplicationHostname: "app-a.internal", ApplicationDisplayName: "App A"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{authorization: auth, authorizationFound: true})

	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/authorizations/"+authID.String(), "any-cookie-value", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["application_hostname"] != "app-a.internal" || body["application_display_name"] != "App A" {
		t.Errorf("unexpected application fields: %+v", body)
	}
}

func TestListAuthorizations_MineFilterResolvesToCallersOwnSubject(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "viewer", CSRFToken: "tok-abc"}
	all := []store.Authorization{{ID: uuid.New()}, {ID: uuid.New()}}
	mine := []store.Authorization{{ID: uuid.New()}}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{authorizations: all, authorizationsMine: mine})

	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/authorizations?mine=true", "any-cookie-value", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Authorizations []struct{ ID string } `json:"authorizations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if len(body.Authorizations) != len(mine) {
		t.Errorf("got %d authorizations, want %d (the \"mine\"-filtered set, not the unfiltered %d)", len(body.Authorizations), len(mine), len(all))
	}

	// Without mine=true, the unfiltered set comes back instead.
	resp2, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/authorizations", "any-cookie-value", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	var body2 struct {
		Authorizations []struct{ ID string } `json:"authorizations"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&body2); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if len(body2.Authorizations) != len(all) {
		t.Errorf("got %d authorizations without mine=true, want %d (the unfiltered set)", len(body2.Authorizations), len(all))
	}
}

func TestAddRequestNote_Success(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "administrator", CSRFToken: "tok-abc"}
	created := store.RequestNote{ID: uuid.New(), AuthorSubject: "user-1", Body: "a note"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{addRequestNoteResult: created}, fakeAdminReadStore{})

	body := strings.NewReader(`{"body":"a note"}`)
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/requests/"+uuid.New().String()+"/notes", "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("got status %d, want 201", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if out["body"] != "a note" || out["author_subject"] != "user-1" {
		t.Errorf("unexpected note body: %+v", out)
	}
}

func TestAddRequestNote_NotFoundMapsTo404(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "administrator", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{addRequestNoteErr: admin.ErrNotFound}, fakeAdminReadStore{})

	body := strings.NewReader(`{"body":"a note"}`)
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/requests/"+uuid.New().String()+"/notes", "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got status %d, want 404", resp.StatusCode)
	}
}

func TestAddRequestNote_ViewerRoleForbidden(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "viewer", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	body := strings.NewReader(`{"body":"a note"}`)
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/requests/"+uuid.New().String()+"/notes", "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got status %d, want 403 (notes require administrator or application_owner, viewer may only read)", resp.StatusCode)
	}
}

func TestListRequestNotes_ReturnsConfiguredNotes(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "viewer", CSRFToken: "tok-abc"}
	notes := []store.RequestNote{{ID: uuid.New(), Body: "first"}, {ID: uuid.New(), Body: "second"}}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{requestNotes: notes})

	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/requests/"+uuid.New().String()+"/notes", "any-cookie-value", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Notes []struct{ Body string } `json:"notes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if len(body.Notes) != 2 || body.Notes[0].Body != "first" || body.Notes[1].Body != "second" {
		t.Errorf("unexpected notes: %+v", body.Notes)
	}
}

func TestAddAuthorizationNote_Success(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "administrator", CSRFToken: "tok-abc"}
	created := store.AuthorizationNote{ID: uuid.New(), AuthorSubject: "user-1", Body: "a session note"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{addAuthorizationNoteResult: created}, fakeAdminReadStore{})

	body := strings.NewReader(`{"body":"a session note"}`)
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/authorizations/"+uuid.New().String()+"/notes", "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("got status %d, want 201", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if out["body"] != "a session note" {
		t.Errorf("unexpected note body: %+v", out)
	}
}

func TestApproveRequest_Success(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "administrator", CSRFToken: "tok-abc"}
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{approveResult: admin.ApproveResult{AuthorizationID: "auth-1", ExpiresAt: expiresAt}}, fakeAdminReadStore{})

	body := strings.NewReader(`{"version":1,"label":"Reception TV"}`)
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/requests/"+uuid.New().String()+"/approve", "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if out["authorization_id"] != "auth-1" {
		t.Errorf("authorization_id = %v, want auth-1", out["authorization_id"])
	}
}

func TestDenyRequest_RequiresReason(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "administrator", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	body := strings.NewReader(`{"version":1}`)
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/requests/"+uuid.New().String()+"/deny", "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("got status %d, want 422 (reason is required)", resp.StatusCode)
	}
}

func TestBulkRevoke_ReportsPerItemResults(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "administrator", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{revokeErr: admin.ErrConflict}, fakeAdminReadStore{})

	goodID := uuid.New().String()
	payload := `{"reason":"cleanup","items":[{"id":"` + goodID + `","version":1},{"id":"not-a-uuid","version":1}]}`
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/authorizations/bulk-revoke", "any-cookie-value", "tok-abc", strings.NewReader(payload))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200 (bulk endpoints always 200, per-item errors)", resp.StatusCode)
	}

	var out struct {
		Results []struct {
			ID      string `json:"id"`
			Success bool   `json:"success"`
			Error   string `json:"error"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if len(out.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(out.Results))
	}
	if out.Results[0].Success || out.Results[0].Error != "conflict" {
		t.Errorf("result[0] = %+v, want a conflict failure (fakeAdminActions always returns ErrConflict)", out.Results[0])
	}
	if out.Results[1].Success || out.Results[1].Error != "invalid_id" {
		t.Errorf("result[1] = %+v, want an invalid_id failure", out.Results[1])
	}
}

func TestAuditExport_SanitizesFormulaPrefixesAndSetsCSVHeaders(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "viewer", CSRFToken: "tok-abc"}
	reason := "=SUM(A1:A9)"
	events := []store.AuditEvent{{
		ID: uuid.New(), OccurredAt: time.Now(), ActorType: "admin", Action: "application.disabled",
		CorrelationID: uuid.New(), Reason: &reason, Outcome: "success",
	}}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{auditEvents: events})

	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/audit-events/export", "any-cookie-value", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	body := string(bodyBytes)
	if strings.Contains(body, ",=SUM(A1:A9),") {
		t.Errorf("CSV body contains an unsanitized formula-looking value: %q", body)
	}
	if !strings.Contains(body, "'=SUM(A1:A9)") {
		t.Errorf("CSV body missing the sanitized (quote-prefixed) reason value: %q", body)
	}
}

func TestOverview_ReturnsCounts(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "viewer", CSRFToken: "tok-abc"}
	counts := store.OverviewCounts{Pending: 3, Active: 5, ExpiringSoon: 2, RevokedOrExpiredRecent: 1}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{overviewCounts: counts})

	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/overview", "any-cookie-value", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if out["pending"] != float64(3) || out["active"] != float64(5) || out["expiring_soon"] != float64(2) || out["revoked_or_expired_recent"] != float64(1) {
		t.Errorf("unexpected /overview body: %+v", out)
	}
}

// TestAdminAnonymousMode_NoCookieRequired proves NewAdminMux works end
// to end when wired with a real adminsession.Anonymous instead of an
// OIDC-backed session store: GET /api/v1/me succeeds with no cookie at
// all, a mutation succeeds once the caller echoes back the CSRF token
// /me handed it, and CSRF protection still rejects a mismatched token
// -- anonymous mode removes the login gate, not the other admin API
// protections.
func TestAdminAnonymousMode_NoCookieRequired(t *testing.T) {
	anon, err := adminsession.NewAnonymous("vpn-perimeter", "VPN-authenticated operator", "administrator")
	if err != nil {
		t.Fatalf("NewAnonymous: %v", err)
	}
	srv := newAdminServer(t, anon, fakeAdminActions{}, fakeAdminReadStore{})

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/me", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Host = testAdminHost
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/me: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/me with no cookie: got status %d, want 200", resp.StatusCode)
	}
	var me map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatalf("decoding /me body: %v", err)
	}
	if me["subject"] != "vpn-perimeter" || me["role"] != "administrator" {
		t.Errorf("unexpected /me body: %+v", me)
	}
	csrfToken, _ := me["csrf_token"].(string)
	if csrfToken == "" {
		t.Fatal("expected a non-empty csrf_token")
	}

	mutation := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/applications/"+uuid.New().String()+"/enable", "", csrfToken, strings.NewReader(`{"version":1}`))
	resp, err = http.DefaultClient.Do(mutation)
	if err != nil {
		t.Fatalf("POST enable: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("mutation with the correct CSRF token got status %d, want it to reach the (fake) action layer", resp.StatusCode)
	}

	badMutation := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/applications/"+uuid.New().String()+"/enable", "", "wrong-token", strings.NewReader(`{"version":1}`))
	resp, err = http.DefaultClient.Do(badMutation)
	if err != nil {
		t.Fatalf("POST enable with bad CSRF: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("mutation with a wrong CSRF token: got status %d, want 403", resp.StatusCode)
	}
}

// --- ApplicationOwner role ---

func TestApplicationOwner_StaffOnlyEndpointsForbidden(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "owner-1", Role: "application_owner", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	for _, path := range []string{"/api/v1/applications", "/api/v1/overview", "/api/v1/audit-events"} {
		resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+path, "any-cookie-value", "", nil))
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s as application_owner: got status %d, want 403", path, resp.StatusCode)
		}
	}
}

func TestApplicationOwner_ListRequestsEmptyWhenNoOwnedApplications(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "owner-1", Role: "application_owner", CSRFToken: "tok-abc"}
	// requests is non-empty on the fake to prove the handler itself
	// short-circuits to an empty result rather than relying on the
	// (real) store's own SQL restriction, which this fake doesn't model.
	requests := []store.ApprovalRequest{{ID: uuid.New(), ApplicationID: uuid.New()}}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{requests: requests})

	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/requests", "any-cookie-value", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	var body struct {
		Requests []struct{ ID string } `json:"requests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if len(body.Requests) != 0 {
		t.Errorf("got %d requests, want 0 (owner of no applications)", len(body.Requests))
	}
}

func TestApplicationOwner_GetRequestOutsideOwnedApplicationIs404(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "owner-1", Role: "application_owner", CSRFToken: "tok-abc"}
	ownedApp := uuid.New()
	otherApp := uuid.New()
	req := store.ApprovalRequest{ID: uuid.New(), ApplicationID: otherApp}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{
		request: req, requestFound: true, ownedApplicationIDs: []uuid.UUID{ownedApp},
	})

	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/requests/"+req.ID.String(), "any-cookie-value", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got status %d, want 404 (request belongs to an application this owner doesn't own)", resp.StatusCode)
	}
}

func TestApplicationOwner_GetRequestWithinOwnedApplicationSucceeds(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "owner-1", Role: "application_owner", CSRFToken: "tok-abc"}
	ownedApp := uuid.New()
	req := store.ApprovalRequest{ID: uuid.New(), ApplicationID: ownedApp}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{
		request: req, requestFound: true, ownedApplicationIDs: []uuid.UUID{ownedApp},
	})

	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/requests/"+req.ID.String(), "any-cookie-value", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want 200 (request belongs to an application this owner does own)", resp.StatusCode)
	}
}

func TestApplicationOwner_ApproveRequestOutsideOwnedApplicationIs404(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "owner-1", Role: "application_owner", CSRFToken: "tok-abc"}
	ownedApp := uuid.New()
	otherApp := uuid.New()
	req := store.ApprovalRequest{ID: uuid.New(), ApplicationID: otherApp}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{approveResult: admin.ApproveResult{AuthorizationID: "should-not-be-reached"}}, fakeAdminReadStore{
		request: req, requestFound: true, ownedApplicationIDs: []uuid.UUID{ownedApp},
	})

	body := strings.NewReader(`{"version":1}`)
	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodPost, srv.URL+"/api/v1/requests/"+req.ID.String()+"/approve", "any-cookie-value", "tok-abc", body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got status %d, want 404 -- approve must never reach internal/admin for an unowned application's request", resp.StatusCode)
	}
}

func TestApplicationOwner_ApproveRequestWithinOwnedApplicationSucceeds(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "owner-1", Role: "application_owner", CSRFToken: "tok-abc"}
	ownedApp := uuid.New()
	req := store.ApprovalRequest{ID: uuid.New(), ApplicationID: ownedApp}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{approveResult: admin.ApproveResult{AuthorizationID: "auth-1"}}, fakeAdminReadStore{
		request: req, requestFound: true, ownedApplicationIDs: []uuid.UUID{ownedApp},
	})

	body := strings.NewReader(`{"version":1}`)
	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodPost, srv.URL+"/api/v1/requests/"+req.ID.String()+"/approve", "any-cookie-value", "tok-abc", body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if out["authorization_id"] != "auth-1" {
		t.Errorf("authorization_id = %v, want auth-1", out["authorization_id"])
	}
}

func TestApplicationOwner_RevokeAuthorizationOutsideOwnedApplicationIs404(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "owner-1", Role: "application_owner", CSRFToken: "tok-abc"}
	ownedApp := uuid.New()
	otherApp := uuid.New()
	auth := store.Authorization{ID: uuid.New(), ApplicationID: otherApp}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{
		authorization: auth, authorizationFound: true, ownedApplicationIDs: []uuid.UUID{ownedApp},
	})

	body := strings.NewReader(`{"reason":"no longer needed"}`)
	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodPost, srv.URL+"/api/v1/authorizations/"+auth.ID.String()+"/revoke", "any-cookie-value", "tok-abc", body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got status %d, want 404 (authorization belongs to an application this owner doesn't own)", resp.StatusCode)
	}
}

func TestApplicationOwner_RevokeAuthorizationWithinOwnedApplicationSucceeds(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "owner-1", Role: "application_owner", CSRFToken: "tok-abc"}
	ownedApp := uuid.New()
	auth := store.Authorization{ID: uuid.New(), ApplicationID: ownedApp}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{
		authorization: auth, authorizationFound: true, ownedApplicationIDs: []uuid.UUID{ownedApp},
	})

	body := strings.NewReader(`{"reason":"no longer needed"}`)
	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodPost, srv.URL+"/api/v1/authorizations/"+auth.ID.String()+"/revoke", "any-cookie-value", "tok-abc", body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want 200 (authorization belongs to an application this owner does own)", resp.StatusCode)
	}
}

func TestApplicationOwner_CannotGrantOwnership(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "owner-1", Role: "application_owner", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	body := strings.NewReader(`{"subject":"someone-else"}`)
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/applications/"+uuid.New().String()+"/owners", "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got status %d, want 403 (granting ownership is administrator-only, spec: an ApplicationOwner cannot control anything else)", resp.StatusCode)
	}
}

// --- Application owner management (administrator-only) ---

func TestGrantApplicationOwner_RequiresNonEmptySubject(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "admin-1", Role: "administrator", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	body := strings.NewReader(`{"subject":""}`)
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/applications/"+uuid.New().String()+"/owners", "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("got status %d, want 422 (subject is required)", resp.StatusCode)
	}
}

func TestGrantApplicationOwner_Success(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "admin-1", Role: "administrator", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	body := strings.NewReader(`{"subject":"new-owner@example.test"}`)
	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/applications/"+uuid.New().String()+"/owners", "any-cookie-value", "tok-abc", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("got status %d, want 201", resp.StatusCode)
	}
}

func TestRevokeApplicationOwner_Success(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "admin-1", Role: "administrator", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	url := srv.URL + "/api/v1/applications/" + uuid.New().String() + "/owners/" + neturl.PathEscape("owner@example.test")
	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodDelete, url, "any-cookie-value", "tok-abc", nil))
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want 200", resp.StatusCode)
	}
}

func TestListApplicationOwners_ViewerCanRead(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "viewer", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{applicationOwners: []string{"a@example.test", "b@example.test"}})

	resp, err := http.DefaultClient.Do(adminRequest(t, http.MethodGet, srv.URL+"/api/v1/applications/"+uuid.New().String()+"/owners", "any-cookie-value", "", nil))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	var out struct {
		Owners []string `json:"owners"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if len(out.Owners) != 2 {
		t.Errorf("got %d owners, want 2", len(out.Owners))
	}
}

// --- Revocation policy: clear-flag endpoint ---

func TestClearAuthorizationFlag_Success(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "admin-1", Role: "administrator", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/authorizations/"+uuid.New().String()+"/clear-flag", "any-cookie-value", "tok-abc", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want 200", resp.StatusCode)
	}
}

func TestClearAuthorizationFlag_ViewerForbidden(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "user-1", Role: "viewer", CSRFToken: "tok-abc"}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{})

	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/authorizations/"+uuid.New().String()+"/clear-flag", "any-cookie-value", "tok-abc", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got status %d, want 403 (clearing a flag requires administrator or application_owner, viewer may only read)", resp.StatusCode)
	}
}

func TestClearAuthorizationFlag_OwnerOutsideOwnedApplicationIs404(t *testing.T) {
	session := adminsession.SessionInfo{Subject: "owner-1", Role: "application_owner", CSRFToken: "tok-abc"}
	ownedApp := uuid.New()
	otherApp := uuid.New()
	auth := store.Authorization{ID: uuid.New(), ApplicationID: otherApp}
	srv := newAdminServer(t, fakeAdminSessions{session: session}, fakeAdminActions{}, fakeAdminReadStore{
		authorization: auth, authorizationFound: true, ownedApplicationIDs: []uuid.UUID{ownedApp},
	})

	req := adminRequest(t, http.MethodPost, srv.URL+"/api/v1/authorizations/"+auth.ID.String()+"/clear-flag", "any-cookie-value", "tok-abc", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got status %d, want 404 (authorization belongs to an application this owner doesn't own)", resp.StatusCode)
	}
}
