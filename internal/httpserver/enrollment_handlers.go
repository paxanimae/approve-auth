package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/frid-iks/approve-auth/internal/authz"
	"github.com/frid-iks/approve-auth/internal/enrollment"
	"github.com/frid-iks/approve-auth/internal/metrics"
	"github.com/frid-iks/approve-auth/internal/qrcode"
	webpublic "github.com/frid-iks/approve-auth/web/public"
)

// approveQRCodeSizePixels is the waiting page's approve-by-QR code's
// rendered size -- deliberately large: this is meant to be scanned off
// a physical screen from a few feet away, not a phone held close to a
// printed page.
const approveQRCodeSizePixels = 220

// maxSubmitBodyBytes bounds every JSON/form body the public,
// unauthenticated enrollment endpoints accept (endpoint-review.md F1):
// none of label (100 runes), message (500 runes), return_to, or a CSRF
// token legitimately need anywhere near this, even accounting for
// multi-byte UTF-8 and URL-encoding overhead.
const maxSubmitBodyBytes = 16 * 1024

// errPayloadTooLarge and errUnsupportedMediaType are sentinels
// parseSubmitForm/formOrJSONCSRFToken return so their callers can map
// them to 413/415 specifically, instead of the generic 400
// malformed_request every other parse failure gets.
var (
	errPayloadTooLarge      = errors.New("httpserver: request body exceeds the accepted size limit")
	errUnsupportedMediaType = errors.New("httpserver: unsupported content type")
	errTrailingJSONData     = errors.New("httpserver: unexpected trailing data after JSON body")
)

// classifyContentType accepts only the two content types this endpoint
// family ever legitimately receives (endpoint-review.md F1: "accept
// only the intended content types; reject unsupported types
// explicitly") -- an absent or unrecognized Content-Type is rejected,
// not guessed at, since every real caller (a same-origin form post or
// this service's own JS) always sets one.
func classifyContentType(r *http.Request) (isJSON, ok bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return false, false
	}
	switch mediaType {
	case "application/json":
		return true, true
	case "application/x-www-form-urlencoded":
		return false, true
	default:
		return false, false
	}
}

// decodeJSONStrict caps the body at maxSubmitBodyBytes via
// http.MaxBytesReader and rejects any trailing data after the single
// expected JSON value (endpoint-review.md F1: "validate the complete
// JSON document, including trailing data"). A body that hits the byte
// cap during either the initial decode or the trailing-data check
// surfaces as errPayloadTooLarge.
func decodeJSONStrict(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxSubmitBodyBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errPayloadTooLarge
		}
		return err
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errPayloadTooLarge
		}
		if err == nil {
			return errTrailingJSONData
		}
		return err
	}
	return nil
}

// writeParseError maps parseSubmitForm/formOrJSONCSRFToken's error into
// the right response: a small, explicit set of statuses rather than
// folding every parse failure into 400.
func writeParseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errPayloadTooLarge):
		writeAPIError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body exceeds the accepted size limit")
	case errors.Is(err, errUnsupportedMediaType):
		writeAPIError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "content type must be application/json or application/x-www-form-urlencoded")
	default:
		writeAPIError(w, http.StatusBadRequest, "malformed_request", "could not parse request body")
	}
}

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
	return stripPort(r.Host)
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

// clientIP resolves the caller's IP for the Public listener's handlers
// -- see publicClientIP's own comment (endpoint-review.md F2) for why
// this differs from the mTLS Authorization listener's clientAddr.
func clientIP(r *http.Request, trustedCIDRs []*net.IPNet) string {
	return publicClientIP(r, trustedCIDRs)
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
	case errors.Is(err, enrollment.ErrAnonymousMessageNotAllowed):
		writeAPIError(w, http.StatusUnprocessableEntity, "messages_not_allowed", "this application does not accept a label or message with the request")
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
	case errors.Is(err, enrollment.ErrAnonymousMessageNotAllowed):
		return "messages_not_allowed"
	default:
		return "internal_error"
	}
}

// --- GET /__approve-auth/request ---

type requestPageData struct {
	DisplayName string
	Hostname    string
	ContactInfo string
	CSRFToken   string
	ReturnTo    string
	// AllowAnonymousMessage: see enrollment.BootstrapResult's own
	// comment (endpoint-review.md F3) -- purely a UX decision about
	// which fields to render; SubmitRequest enforces the real policy
	// server-side regardless.
	AllowAnonymousMessage bool
}

func requestPageHandler(enroller Enroller, requestTTL time.Duration, trustedCIDRs []*net.IPNet) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		existingPending, ok := singleCookieValue(r, pendingCookieName)
		if !ok {
			writeAPIError(w, http.StatusBadRequest, "malformed_cookie", "duplicate pending-request cookie")
			return
		}

		result, err := enroller.Bootstrap(r.Context(), enrollment.BootstrapInput{
			Hostname:             requestHostname(r),
			ExistingPendingToken: existingPending,
			ClientIP:             clientIP(r, trustedCIDRs),
		})
		if err != nil {
			mapEnrollmentError(w, err)
			return
		}
		if result.RawPendingToken != "" {
			setCookie(w, pendingCookieName, result.RawPendingToken, requestTTL)
		}

		renderPage(w, "request.html.tmpl", requestPageData{
			DisplayName:           result.ApplicationDisplayName,
			Hostname:              result.ApplicationHostname,
			ContactInfo:           result.ContactInfo,
			CSRFToken:             result.CSRFToken,
			ReturnTo:              validateQueryReturnTo(r),
			AllowAnonymousMessage: result.AllowAnonymousMessage,
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

// --- POST /__approve-auth/requests ---

func submitRequestHandler(enroller Enroller, trustedCIDRs []*net.IPNet) http.HandlerFunc {
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

		label, message, returnTo, csrfToken, err := parseSubmitForm(w, r)
		if err != nil {
			writeParseError(w, err)
			return
		}

		result, err := enroller.SubmitRequest(r.Context(), enrollment.SubmitRequestInput{
			PendingTokenRaw: pendingToken, CSRFToken: csrfToken,
			Label: label, Message: message, ReturnTo: returnTo,
			ClientIP: clientIP(r, trustedCIDRs), UserAgent: r.Header.Get("User-Agent"),
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
		http.Redirect(w, r, "/__approve-auth/waiting", http.StatusSeeOther)
	}
}

func parseSubmitForm(w http.ResponseWriter, r *http.Request) (label, message, returnTo, csrfToken string, err error) {
	isJSON, ok := classifyContentType(r)
	if !ok {
		return "", "", "", "", errUnsupportedMediaType
	}
	if isJSON {
		var body struct {
			Label     string `json:"label"`
			Message   string `json:"message"`
			ReturnTo  string `json:"return_to"`
			CSRFToken string `json:"csrf_token"`
		}
		if err := decodeJSONStrict(w, r, &body); err != nil {
			return "", "", "", "", err
		}
		return body.Label, body.Message, body.ReturnTo, body.CSRFToken, nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSubmitBodyBytes)
	if err := r.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return "", "", "", "", errPayloadTooLarge
		}
		return "", "", "", "", err
	}
	return r.PostForm.Get("label"), r.PostForm.Get("message"), r.PostForm.Get("return_to"), r.PostForm.Get("csrf_token"), nil
}

func formOrJSONCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	isJSON, ok := classifyContentType(r)
	if !ok {
		return "", errUnsupportedMediaType
	}
	if isJSON {
		var body struct {
			CSRFToken string `json:"csrf_token"`
		}
		if err := decodeJSONStrict(w, r, &body); err != nil {
			return "", err
		}
		return body.CSRFToken, nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSubmitBodyBytes)
	if err := r.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return "", errPayloadTooLarge
		}
		return "", err
	}
	return r.PostForm.Get("csrf_token"), nil
}

// --- GET /__approve-auth/waiting ---

type waitingPageData struct {
	State            string
	VerificationCode string
	PublicMessage    string
	CSRFToken        string
	HasAccessCookie  bool
	// ApproveQRCodeSVG is set only while State is "pending" -- an inline
	// <svg> (safe to emit unescaped: built entirely from this service's
	// own AdminOrigin config and a UUID, never requester-controlled)
	// encoding a deep link into the admin console for whoever has
	// approval rights over this application to scan and act on from
	// their phone.
	ApproveQRCodeSVG template.HTML
}

func waitingPageHandler(enroller Enroller, adminOrigin string) http.HandlerFunc {
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
				if status.State == "pending" && status.RequestID != "" {
					data.ApproveQRCodeSVG = approveQRCodeSVG(adminOrigin, status.RequestID)
				}
			}
		}
		if accessToken, ok := singleCookieValue(r, accessCookieName); ok && accessToken != "" {
			data.HasAccessCookie = true
		}

		renderPage(w, "waiting.html.tmpl", data)
	}
}

// approveQRCodeSVG builds the admin-console deep-link URL
// (adminOrigin + "/?open_request=<id>") and renders it as an inline QR
// code. A failure here is advisory, not fatal -- the waiting page
// remains fully usable via the verification code alone (spec's
// existing no-JS/no-QR path), so a rendering error is logged and the
// QR is simply omitted rather than failing the whole page.
func approveQRCodeSVG(adminOrigin, requestID string) template.HTML {
	if adminOrigin == "" {
		return ""
	}
	target := adminOrigin + "/?open_request=" + url.QueryEscape(requestID)
	svg, err := qrcode.SVG(target, approveQRCodeSizePixels)
	if err != nil {
		log.Printf("httpserver: rendering approve QR code: %v", err)
		return ""
	}
	return template.HTML(svg)
}

// --- GET /__approve-auth/status ---

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

// --- POST /__approve-auth/cancel ---

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
		csrfToken, err := formOrJSONCSRFToken(w, r)
		if err != nil {
			writeParseError(w, err)
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
		http.Redirect(w, r, "/__approve-auth/waiting", http.StatusSeeOther)
	}
}

// --- POST /__approve-auth/claim ---

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
		csrfToken, err := formOrJSONCSRFToken(w, r)
		if err != nil {
			writeParseError(w, err)
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
		http.Redirect(w, r, "/__approve-auth/waiting", http.StatusSeeOther)
	}
}

// --- GET /__approve-auth/session ---

func sessionHandler(decider Decider, decisionTimeout time.Duration, trustedCIDRs []*net.IPNet) http.HandlerFunc {
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
			ClientAddr:  clientIP(r, trustedCIDRs),
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

// --- POST /__approve-auth/ack ---

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

// --- POST /__approve-auth/logout ---

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
