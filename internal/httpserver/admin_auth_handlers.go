package httpserver

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/frid-iks/approve-auth/internal/adminsession"
)

// --- GET /auth/login ---

// adminLoginHandler starts the OIDC flow (spec section 9). No CSRF/Origin
// check applies here: this is a top-level browser navigation, either the
// console's own "log in" link or a bookmark, not a state-changing request.
// decisionTimeout bounds BeginLogin's database write the same way
// NewAuthMux bounds a ForwardAuth decision: a stuck query or a dead pooled
// connection then fails fast with a 500 instead of hanging the request (and
// the browser) indefinitely with no response at all.
func adminLoginHandler(sessions AdminSessions, decisionTimeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), decisionTimeout)
		defer cancel()
		result, err := sessions.BeginLogin(ctx, r.URL.Query().Get("return_to"))
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to start login")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, result.RedirectURL, http.StatusFound)
	}
}

// --- GET /auth/callback ---

// adminCallbackHandler completes the flow and sets the admin session
// cookie. Protected by the OIDC state parameter itself, not a same-origin
// check -- the redirect back here legitimately originates from the IdP.
// decisionTimeout bounds HandleCallback the same way it bounds
// adminLoginHandler above -- this also covers the code-exchange call to the
// IdP itself, not just the database, since a hung upstream token endpoint
// is exactly as capable of leaving this request permanently unanswered.
func adminCallbackHandler(sessions AdminSessions, sessionCookieMaxAge, decisionTimeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		if state == "" || code == "" {
			writeAPIError(w, http.StatusBadRequest, "malformed_request", "missing state or code")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), decisionTimeout)
		defer cancel()
		rawToken, returnPath, err := sessions.HandleCallback(ctx, state, code)
		if err != nil {
			mapAdminSessionError(w, err)
			return
		}

		setCookie(w, adminCookieName, rawToken, sessionCookieMaxAge)
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, returnPath, http.StatusSeeOther)
	}
}

// --- POST /auth/logout ---

// adminLogoutHandler is wrapped with requireAdminSession + requireAdminCSRF
// like every other mutation (spec section 9: "CSRF protection for every
// mutation, including logout"); adminsession.Logout independently
// revalidates the same token against the session's stored secret.
func adminLogoutHandler(sessions AdminSessions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, _ := singleCookieValue(r, adminCookieName)
		if err := sessions.Logout(r.Context(), token, r.Header.Get(csrfHeaderName)); err != nil {
			if errors.Is(err, adminsession.ErrInvalidCSRF) {
				writeAPIError(w, http.StatusForbidden, "invalid_csrf", "invalid or missing CSRF token")
				return
			}
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "logout failed")
			return
		}
		clearCookie(w, adminCookieName)
		writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})
	}
}

// --- GET /api/v1/me ---

// adminMeHandler returns the caller's own identity, role, and CSRF token
// -- the console's bootstrap call, and how it discovers the token it
// must echo back on every mutation. It also carries the server's
// configured default/max authorization duration so the console's
// approve/renew forms can offer a "permanent" option that means
// something real (the longest duration Approve/Renew will actually
// accept) instead of a client-side guess that might get rejected.
func adminMeHandler(defaultAuthorizationDuration, maxAuthorizationDuration time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, ok := adminIdentityFromContext(r.Context())
		if !ok {
			writeAPIError(w, http.StatusUnauthorized, "no_session", "no active admin session")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"subject":                                info.Subject,
			"display_name":                           info.DisplayName,
			"role":                                   info.Role,
			"csrf_token":                             info.CSRFToken,
			"default_authorization_duration_seconds": int64(defaultAuthorizationDuration.Seconds()),
			"max_authorization_duration_seconds":     int64(maxAuthorizationDuration.Seconds()),
		})
	}
}

func mapAdminSessionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, adminsession.ErrInvalidState):
		writeAPIError(w, http.StatusBadRequest, "invalid_state", "invalid, expired, or already-used login attempt -- please try again")
	case errors.Is(err, adminsession.ErrNoAccess):
		writeAPIError(w, http.StatusForbidden, "no_access", "your account is not authorized to access this console")
	default:
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "login failed")
	}
}
