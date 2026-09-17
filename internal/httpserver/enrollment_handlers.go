package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/frid-iks/traefik-manual-proxy/internal/authz"
	"github.com/frid-iks/traefik-manual-proxy/internal/enrollment"
	"github.com/frid-iks/traefik-manual-proxy/internal/metrics"
	webpublic "github.com/frid-iks/traefik-manual-proxy/web/public"
)

// Enroller is the internal/enrollment.Service surface the public
// listener's handlers need.
type Enroller interface {
	Bootstrap(ctx context.Context, in enrollment.BootstrapInput) (enrollment.BootstrapResult, error)
	SubmitRequest(ctx context.Context, in enrollment.SubmitRequestInput) (enrollment.SubmitRequestResult, error)
	Status(ctx context.Context, pendingTokenRaw string) (enrollment.StatusResult, error)
	Cancel(ctx context.Context, pendingTokenRaw, csrfToken string) error
	Claim(ctx context.Context, pendingTokenRaw, csrfToken string) (enrollment.ClaimOutcome, error)
	Ack(ctx context.Context, pendingTokenRaw string) (string, error)
	Logout(ctx context.Context, hostname, accessCookieValue string) error
}

var pageTemplates = template.Must(template.ParseFS(webpublic.Templates, "templates/*.tmpl"))

// requestHostname strips a port suffix (if the caller included one) --
// applications are registered without one (spec section 3 rejects
// non-443 ports at registration time), and on the Public listener the
// Host header is the browser's original one verbatim (Traefik proxies
// with passHostHeader: true by default), no forwarded-header parsing
// needed the way the mTLS Authorization listener requires.
func requestHostname(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

func wantsJSON(r *http.Request) bool {
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		return true
	}
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
}

// checkOrigin implements spec section 9: exact Origin match; if Origin
// is absent, a same-origin Referer is required instead; absent both is
// rejected.
//
// A literal "null" Origin is treated the same as an absent one, not as
// a non-matching value: browsers legitimately send this opaque value
// for same-origin requests in some redirect/navigation contexts (e.g.
// spec section 5 step 1's own /auth-issued 303 redirect into the
// request page), not just from a sandboxed or attacker-controlled
// context. Falling through to the Referer check here costs nothing
// against a real cross-origin attacker: their own page's form
// submission carries their own Origin, never the literal string "null".
func checkOrigin(r *http.Request) bool {
	expected := "https://" + r.Host
	if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
		return origin == expected
	}
	referer := r.Header.Get("Referer")
	if referer == "" {
		return false
	}
	u, err := url.Parse(referer)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host == r.Host
}

func clientIP(r *http.Request) string {
	return clientAddr(r)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func renderPage(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := pageTemplates.ExecuteTemplate(w, name, data); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "render_error", "failed to render page")
	}
}

// mapEnrollmentError centralizes the enrollment-package-error -> HTTP
// mapping every mutating handler below needs.
func mapEnrollmentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, enrollment.ErrApplicationUnavailable):
		writeAPIError(w, http.StatusForbidden, "application_unavailable", "this application is not available")
	case errors.Is(err, enrollment.ErrInvalidPendingProof):
		writeAPIError(w, http.StatusUnauthorized, "invalid_pending_proof", "no valid pending request found -- please start again")
	case errors.Is(err, enrollment.ErrInvalidCSRF):
		writeAPIError(w, http.StatusForbidden, "invalid_csrf", "invalid or missing CSRF token")
	case errors.Is(err, enrollment.ErrRateLimited):
		writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "too many requests -- please try again later")
	case errors.Is(err, enrollment.ErrNotClaimable):
		writeAPIError(w, http.StatusConflict, "not_claimable", "this request is no longer in a state that allows this action")
	case errors.Is(err, enrollment.ErrAlreadyClaimedNoEnvelope):
		writeAPIError(w, http.StatusUnauthorized, "claim_expired", "the claim window has passed -- please request access again")
	default:
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "an internal error occurred")
	}
}

// enrollmentErrorReason is a fixed, low-cardinality label for spec
// section 15's "poll and claim errors" metrics -- never the raw error
// string, which could embed request-specific detail.
func enrollmentErrorReason(err error) string {
	switch {
	case errors.Is(err, enrollment.ErrApplicationUnavailable):
		return "application_unavailable"
	case errors.Is(err, enrollment.ErrInvalidPendingProof):
		return "invalid_pending_proof"
	case errors.Is(err, enrollment.ErrInvalidCSRF):
		return "invalid_csrf"
	case errors.Is(err, enrollment.ErrRateLimited):
		return "rate_limited"
	case errors.Is(err, enrollment.ErrNotClaimable):
		return "not_claimable"
	case errors.Is(err, enrollment.ErrAlreadyClaimedNoEnvelope):
		return "claim_expired"
	default:
		return "internal_error"
	}
}

// --- GET /__manual-approval/request ---

type requestPageData struct {
	DisplayName string
	Hostname    string
	CSRFToken   string
	ReturnTo    string
}

func requestPageHandler(enroller Enroller, requestTTL time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		existingPending, ok := singleCookieValue(r, pendingCookieName)
		if !ok {
			writeAPIError(w, http.StatusBadRequest, "malformed_cookie", "duplicate pending-request cookie")
			return
		}

		result, err := enroller.Bootstrap(r.Context(), enrollment.BootstrapInput{
			Hostname:             requestHostname(r),
			ExistingPendingToken: existingPending,
			ClientIP:             clientIP(r),
		})
		if err != nil {
			mapEnrollmentError(w, err)
			return
		}
		if result.RawPendingToken != "" {
			setCookie(w, pendingCookieName, result.RawPendingToken, requestTTL)
		}

		renderPage(w, "request.html.tmpl", requestPageData{
			DisplayName: result.ApplicationDisplayName,
			Hostname:    result.ApplicationHostname,
			CSRFToken:   result.CSRFToken,
			ReturnTo:    validateQueryReturnTo(r),
		})
	}
}

// validateQueryReturnTo is a light pass-through for display/threading
// purposes only -- SubmitRequest validates the real value again server-
// side before it's ever persisted or redirected to (spec section 5:
// "Validate on entry and again before redirect").
func validateQueryReturnTo(r *http.Request) string {
	v := r.URL.Query().Get("return_to")
	if v == "" || !strings.HasPrefix(v, "/") {
		return "/"
	}
	return v
}

// --- POST /__manual-approval/requests ---

func submitRequestHandler(enroller Enroller) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkOrigin(r) {
			writeAPIError(w, http.StatusForbidden, "bad_origin", "request did not originate from this host")
			return
		}
		pendingToken, ok := singleCookieValue(r, pendingCookieName)
		if !ok {
			writeAPIError(w, http.StatusBadRequest, "malformed_cookie", "duplicate pending-request cookie")
			return
		}
		if pendingToken == "" {
			writeAPIError(w, http.StatusBadRequest, "cookies_required", "this service requires cookies to be enabled")
			return
		}

		label, message, returnTo, csrfToken, err := parseSubmitForm(r)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "malformed_request", "could not parse request body")
			return
		}

		result, err := enroller.SubmitRequest(r.Context(), enrollment.SubmitRequestInput{
			PendingTokenRaw: pendingToken, CSRFToken: csrfToken,
			Label: label, Message: message, ReturnTo: returnTo,
			ClientIP: clientIP(r), UserAgent: r.Header.Get("User-Agent"),
		})
		if err != nil {
			mapEnrollmentError(w, err)
			return
		}

		if wantsJSON(r) {
			writeJSON(w, http.StatusCreated, result)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, "/__manual-approval/waiting", http.StatusSeeOther)
	}
}

func parseSubmitForm(r *http.Request) (label, message, returnTo, csrfToken string, err error) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Label     string `json:"label"`
			Message   string `json:"message"`
			ReturnTo  string `json:"return_to"`
			CSRFToken string `json:"csrf_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return "", "", "", "", err
		}
		return body.Label, body.Message, body.ReturnTo, body.CSRFToken, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", "", "", "", err
	}
	return r.PostForm.Get("label"), r.PostForm.Get("message"), r.PostForm.Get("return_to"), r.PostForm.Get("csrf_token"), nil
}

func formOrJSONCSRFToken(r *http.Request) (string, error) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			CSRFToken string `json:"csrf_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return "", err
		}
		return body.CSRFToken, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", err
	}
	return r.PostForm.Get("csrf_token"), nil
}

// --- GET /__manual-approval/waiting ---

type waitingPageData struct {
	State            string
	VerificationCode string
	PublicMessage    string
	CSRFToken        string
	HasAccessCookie  bool
}

func waitingPageHandler(enroller Enroller) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pendingToken, ok := singleCookieValue(r, pendingCookieName)
		if !ok {
			writeAPIError(w, http.StatusBadRequest, "malformed_cookie", "duplicate pending-request cookie")
			return
		}

		data := waitingPageData{State: "not_requested"}
		if pendingToken != "" {
			status, err := enroller.Status(r.Context(), pendingToken)
			if err != nil && !errors.Is(err, enrollment.ErrInvalidPendingProof) {
				mapEnrollmentError(w, err)
				return
			}
			if err == nil {
				data.State = status.State
				data.VerificationCode = status.VerificationCode
				data.PublicMessage = status.PublicMessage
				data.CSRFToken = status.CSRFToken
			}
		}
		if accessToken, ok := singleCookieValue(r, accessCookieName); ok && accessToken != "" {
			data.HasAccessCookie = true
		}

		renderPage(w, "waiting.html.tmpl", data)
	}
}

// --- GET /__manual-approval/status ---

func statusHandler(enroller Enroller) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pendingToken, ok := singleCookieValue(r, pendingCookieName)
		if !ok || pendingToken == "" {
			writeJSON(w, http.StatusOK, map[string]any{"state": "not_requested", "server_time": time.Now()})
			return
		}
		status, err := enroller.Status(r.Context(), pendingToken)
		if err != nil {
			if errors.Is(err, enrollment.ErrInvalidPendingProof) {
				writeJSON(w, http.StatusOK, map[string]any{"state": "not_requested", "server_time": time.Now()})
				return
			}
			metrics.PollErrors.WithLabelValues(enrollmentErrorReason(err)).Inc()
			mapEnrollmentError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, status)
	}
}

// --- POST /__manual-approval/cancel ---

func cancelHandler(enroller Enroller) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkOrigin(r) {
			writeAPIError(w, http.StatusForbidden, "bad_origin", "request did not originate from this host")
			return
		}
		pendingToken, ok := singleCookieValue(r, pendingCookieName)
		if !ok || pendingToken == "" {
			writeAPIError(w, http.StatusBadRequest, "invalid_pending_proof", "no pending request cookie")
			return
		}
		csrfToken, err := formOrJSONCSRFToken(r)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "malformed_request", "could not parse request body")
			return
		}
		if err := enroller.Cancel(r.Context(), pendingToken, csrfToken); err != nil {
			mapEnrollmentError(w, err)
			return
		}
		if wantsJSON(r) {
			writeJSON(w, http.StatusOK, map[string]any{"canceled": true})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, "/__manual-approval/waiting", http.StatusSeeOther)
	}
}

// --- POST /__manual-approval/claim ---

func claimHandler(enroller Enroller, credentialCookieMaxAge time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkOrigin(r) {
			writeAPIError(w, http.StatusForbidden, "bad_origin", "request did not originate from this host")
			return
		}
		pendingToken, ok := singleCookieValue(r, pendingCookieName)
		if !ok || pendingToken == "" {
			writeAPIError(w, http.StatusBadRequest, "invalid_pending_proof", "no pending request cookie")
			return
		}
		csrfToken, err := formOrJSONCSRFToken(r)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "malformed_request", "could not parse request body")
			return
		}

		outcome, err := enroller.Claim(r.Context(), pendingToken, csrfToken)
		if err != nil {
			metrics.ClaimErrors.WithLabelValues(enrollmentErrorReason(err)).Inc()
			mapEnrollmentError(w, err)
			return
		}

		setCookie(w, accessCookieName, outcome.RawAccessToken, credentialCookieMaxAge)

		if wantsJSON(r) {
			writeJSON(w, http.StatusOK, map[string]any{"return_to": outcome.ReturnTo})
			return
		}
		// spec section 5, step 7 (no-JS path): the HTML claim response
		// sets the cookie and returns to the waiting page, which then
		// detects the active cookie and offers the ack ("Open
		// application") form -- it does not jump straight to ReturnTo.
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, "/__manual-approval/waiting", http.StatusSeeOther)
	}
}

// --- GET /__manual-approval/session ---

func sessionHandler(decider Decider, decisionTimeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accessToken, ok := singleCookieValue(r, accessCookieName)
		if !ok {
			writeAPIError(w, http.StatusBadRequest, "malformed_cookie", "duplicate access cookie")
			return
		}
		if accessToken == "" {
			writeAPIError(w, http.StatusUnauthorized, "no_session", "no active session")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), decisionTimeout)
		defer cancel()
		decision, err := decider.Decide(ctx, authz.AuthRequest{
			Host:        requestHostname(r),
			Method:      http.MethodGet,
			CookieValue: accessToken,
			ClientAddr:  clientIP(r),
			UserAgent:   r.Header.Get("User-Agent"),
		})
		if err != nil {
			writeAPIError(w, http.StatusServiceUnavailable, "decision_unavailable", "session check temporarily unavailable")
			return
		}
		if decision.Category != authz.CategoryAllow {
			writeAPIError(w, http.StatusUnauthorized, "no_session", "no active session")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"active": true})
	}
}

// --- POST /__manual-approval/ack ---

func ackHandler(enroller Enroller) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkOrigin(r) {
			writeAPIError(w, http.StatusForbidden, "bad_origin", "request did not originate from this host")
			return
		}
		pendingToken, ok := singleCookieValue(r, pendingCookieName)
		if !ok || pendingToken == "" {
			writeAPIError(w, http.StatusBadRequest, "invalid_pending_proof", "no pending request cookie")
			return
		}
		if accessToken, ok := singleCookieValue(r, accessCookieName); !ok || accessToken == "" {
			writeAPIError(w, http.StatusUnauthorized, "no_session", "no active access cookie to acknowledge")
			return
		}

		returnTo, err := enroller.Ack(r.Context(), pendingToken)
		if err != nil {
			mapEnrollmentError(w, err)
			return
		}
		clearCookie(w, pendingCookieName)

		if wantsJSON(r) {
			writeJSON(w, http.StatusOK, map[string]any{"return_to": returnTo})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, returnTo, http.StatusSeeOther)
	}
}

// --- POST /__manual-approval/logout ---

func logoutHandler(enroller Enroller) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkOrigin(r) {
			writeAPIError(w, http.StatusForbidden, "bad_origin", "request did not originate from this host")
			return
		}
		accessToken, _ := singleCookieValue(r, accessCookieName)
		if err := enroller.Logout(r.Context(), requestHostname(r), accessToken); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "logout failed")
			return
		}
		clearCookie(w, accessCookieName)
		clearCookie(w, pendingCookieName)
		writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})
	}
}
