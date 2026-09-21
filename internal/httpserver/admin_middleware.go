package httpserver

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/paxanimae/approve-auth/internal/admin"
	"github.com/paxanimae/approve-auth/internal/adminsession"
)

// csrfHeaderName carries the admin API's synchronizer token (spec
// section 9: "CSRF token ... for every [admin] mutation"). Unlike the
// public listener's HTML-form CSRF field, the admin console is a JSON
// API, so the token travels as a header on every mutating request.
const csrfHeaderName = "X-CSRF-Token"

// AdminSessions is the internal/adminsession.Service surface the admin
// listener's handlers need.
type AdminSessions interface {
	BeginLogin(ctx context.Context, returnTo string) (adminsession.BeginLoginResult, error)
	HandleCallback(ctx context.Context, state, code string) (rawSessionToken, returnPath string, err error)
	ValidateSession(ctx context.Context, rawToken string) (adminsession.SessionInfo, error)
	Logout(ctx context.Context, rawToken, csrfToken string) error
}

type adminIdentityContextKey struct{}

func adminIdentityFromContext(ctx context.Context) (adminsession.SessionInfo, bool) {
	info, ok := ctx.Value(adminIdentityContextKey{}).(adminsession.SessionInfo)
	return info, ok
}

// actorSubject is every mutation handler's audit-actor value: the OIDC
// subject of the caller requireAdminSession already validated. Empty
// only if called outside that middleware, which no route does.
func actorSubject(r *http.Request) string {
	if info, ok := adminIdentityFromContext(r.Context()); ok {
		return info.Subject
	}
	return ""
}

// adminErrorDetails centralizes internal/admin's error -> HTTP mapping
// (spec section 9's status codes) so both a single-item mutation
// handler and a bulk handler's per-item result can use the same mapping.
func adminErrorDetails(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, admin.ErrConflict):
		return http.StatusConflict, "conflict", "the record was modified by someone else -- reload and try again"
	case errors.Is(err, admin.ErrInvalidExpiry):
		return http.StatusUnprocessableEntity, "invalid_expiry", "expires_at must be in the future and within the configured maximum duration"
	case errors.Is(err, admin.ErrDuplicateHostname):
		return http.StatusConflict, "duplicate_hostname", "an application with this hostname is already registered"
	case errors.Is(err, admin.ErrInvalidDuration):
		return http.StatusUnprocessableEntity, "invalid_duration", "default_duration and max_duration must be positive, with default_duration <= max_duration"
	case errors.Is(err, admin.ErrNotFound):
		return http.StatusNotFound, "not_found", "no such record"
	case errors.Is(err, admin.ErrInvalidNote):
		return http.StatusUnprocessableEntity, "invalid_note", "note body must be between 1 and 2000 characters"
	case errors.Is(err, admin.ErrInvalidRevocationThreshold):
		return http.StatusUnprocessableEntity, "invalid_input", "revocation_inactivity_threshold_seconds must be positive"
	case errors.Is(err, admin.ErrInvalidMessageRetention):
		return http.StatusUnprocessableEntity, "invalid_input", "message_retention_seconds must be positive"
	default:
		return http.StatusInternalServerError, "internal_error", "the request could not be completed"
	}
}

func mapAdminError(w http.ResponseWriter, err error) {
	status, code, message := adminErrorDetails(err)
	writeAPIError(w, status, code, message)
}

// requireAdminHost implements spec section 9: "Verify admin Host equals
// configured admin hostname." Applied per registered route (folded into
// NewAdminMux's authed/mutating helpers) rather than around the whole
// mux: a path nobody registered must still 404 from the mux itself --
// the cross-listener-isolation exit gate (spec section 2) checks other
// listeners' routes against this one and expects exactly 404, not a
// Host-check 403 that would fire before the mux even looks at the path.
func requireAdminHost(adminHost string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requestHostname(r) != adminHost {
			writeAPIError(w, http.StatusForbidden, "unknown_host", "this host is not configured for admin access")
			return
		}
		next(w, r)
	}
}

// requireAdminSession resolves the admin session cookie to a live
// session of any role and stores it in the request context; on failure
// it writes 401 and never calls next. Every /api/v1 route needs at least
// this; requireAdministrator further restricts mutations.
func requireAdminSession(sessions AdminSessions, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := singleCookieValue(r, adminCookieName)
		if !ok {
			writeAPIError(w, http.StatusBadRequest, "malformed_cookie", "duplicate admin session cookie")
			return
		}
		info, err := sessions.ValidateSession(r.Context(), token)
		if err != nil {
			writeAPIError(w, http.StatusUnauthorized, "no_session", "no active admin session")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, info)))
	}
}

// requireAdministrator further restricts a requireAdminSession-wrapped
// handler to the administrator role (spec section 9: "viewer reads
// operational state and audit; administrator also mutates").
func requireAdministrator(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, ok := adminIdentityFromContext(r.Context())
		if !ok || info.Role != "administrator" {
			writeAPIError(w, http.StatusForbidden, "forbidden", "administrator role required")
			return
		}
		next(w, r)
	}
}

// requireStaffRole restricts a requireAdminSession-wrapped handler to
// administrator or viewer, excluding application_owner. An
// ApplicationOwner "cannot control anything else" beyond their own
// application's requests/authorizations (spec) -- applications
// management, the overview dashboard, and the audit log have no
// per-resource ownership check to scope by, so they're off-limits to
// that role entirely rather than partially filtered.
func requireStaffRole(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, ok := adminIdentityFromContext(r.Context())
		if !ok || (info.Role != "administrator" && info.Role != "viewer") {
			writeAPIError(w, http.StatusForbidden, "forbidden", "administrator or viewer role required")
			return
		}
		next(w, r)
	}
}

// requireAdministratorOrOwner permits the administrator role
// unconditionally, or application_owner subject to a per-resource
// ownership check the handler itself performs (via
// ownedApplicationIDsForCaller) -- unlike requireAdministrator, this
// middleware alone is not sufficient authorization for the request to
// proceed, only a prerequisite for it.
func requireAdministratorOrOwner(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, ok := adminIdentityFromContext(r.Context())
		if !ok || (info.Role != "administrator" && info.Role != "application_owner") {
			writeAPIError(w, http.StatusForbidden, "forbidden", "administrator or application_owner role required")
			return
		}
		next(w, r)
	}
}

// ownedApplicationIDsForCaller resolves the caller's owned-application
// set when their role is application_owner, and reports restricted=false
// for every other role (administrator/viewer see everything, with a nil
// restriction slice). Resolved fresh on every call rather than trusting
// anything cached on the session, matching GetOwnedApplicationIDs' own
// freshness rationale.
func ownedApplicationIDsForCaller(r *http.Request, readStore AdminReadStore) (restrict []uuid.UUID, restricted bool, err error) {
	info, ok := adminIdentityFromContext(r.Context())
	if !ok || info.Role != "application_owner" {
		return nil, false, nil
	}
	owned, err := readStore.GetOwnedApplicationIDs(r.Context(), info.Subject)
	if err != nil {
		return nil, true, fmt.Errorf("httpserver: resolving owned applications: %w", err)
	}
	return owned, true, nil
}

// authorizeOwnedResource enforces requireAdministratorOrOwner's deferred
// half for a single existing resource: an administrator always passes;
// an application_owner passes only if applicationID is in their
// currently-owned set. Returns false (having already written the
// response) if the caller must not proceed -- a 404, not 403, so an
// owner probing another application's resource IDs learns nothing about
// whether they exist (matching how a missing resource already responds).
func authorizeOwnedResource(w http.ResponseWriter, r *http.Request, readStore AdminReadStore, applicationID uuid.UUID, notFoundCode, notFoundMessage string) bool {
	info, ok := adminIdentityFromContext(r.Context())
	if !ok || info.Role != "application_owner" {
		// administrator and viewer both see everything unrestricted;
		// only application_owner is scoped to a per-resource check.
		return true
	}
	owned, err := readStore.GetOwnedApplicationIDs(r.Context(), info.Subject)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to resolve application ownership")
		return false
	}
	for _, id := range owned {
		if id == applicationID {
			return true
		}
	}
	writeAPIError(w, http.StatusNotFound, notFoundCode, notFoundMessage)
	return false
}

// authorizeOwnedRequest resolves a request by id and checks ownership
// via authorizeOwnedResource -- shared by every request-scoped mutation
// handler (approve, deny, add note) that ownerMutating protects. It
// skips the extra fetch entirely for administrator (and any other
// non-application_owner role), preserving exactly the pre-existing
// behavior of leaving existence/conflict handling to internal/admin's
// own ErrConflict/ErrNotFound mapping for that path.
func authorizeOwnedRequest(w http.ResponseWriter, r *http.Request, readStore AdminReadStore, id uuid.UUID) bool {
	info, ok := adminIdentityFromContext(r.Context())
	if !ok || info.Role != "application_owner" {
		return true
	}
	req, found, err := readStore.GetApprovalRequestByID(r.Context(), id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to load request")
		return false
	}
	if !found {
		writeAPIError(w, http.StatusNotFound, "not_found", "no such request")
		return false
	}
	return authorizeOwnedResource(w, r, readStore, req.ApplicationID, "not_found", "no such request")
}

// authorizeOwnedAuthorization is authorizeOwnedRequest's counterpart for
// authorization-scoped mutations (revoke, add note).
func authorizeOwnedAuthorization(w http.ResponseWriter, r *http.Request, readStore AdminReadStore, id uuid.UUID) bool {
	info, ok := adminIdentityFromContext(r.Context())
	if !ok || info.Role != "application_owner" {
		return true
	}
	auth, found, err := readStore.GetAuthorizationByID(r.Context(), id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to load authorization")
		return false
	}
	if !found {
		writeAPIError(w, http.StatusNotFound, "not_found", "no such authorization")
		return false
	}
	return authorizeOwnedResource(w, r, readStore, auth.ApplicationID, "not_found", "no such authorization")
}

// requireAdminCSRF enforces the synchronizer-token check for a mutation:
// the caller must echo back the session's own derived token, which a
// cross-origin/CSRF request cannot read. Must run after
// requireAdminSession so adminIdentityFromContext is populated.
func requireAdminCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, ok := adminIdentityFromContext(r.Context())
		if !ok {
			writeAPIError(w, http.StatusUnauthorized, "no_session", "no active admin session")
			return
		}
		candidate := r.Header.Get(csrfHeaderName)
		if candidate == "" || subtle.ConstantTimeCompare([]byte(candidate), []byte(info.CSRFToken)) != 1 {
			writeAPIError(w, http.StatusForbidden, "invalid_csrf", "invalid or missing CSRF token")
			return
		}
		next(w, r)
	}
}
