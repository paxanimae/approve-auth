package httpserver

import (
	"net/http"
	"time"
)

// accessCookieName is fixed across every protected application (spec
// section 4): a single __Host- prefixed name, so browsers enforce
// Secure+Path=/+no-Domain on it themselves, and the server additionally
// binds each credential to its own application (see internal/authz).
const accessCookieName = "__Host-approve-auth"

// pendingCookieName carries the enrollment pending proof (spec section
// 4): same cookie attributes as accessCookieName, shorter lifetime.
const pendingCookieName = "__Host-approve-auth-request"

// adminCookieName carries the admin console's own session, distinct from
// both the enrollment cookies above and the per-application access
// cookie (spec section 4: "Use separate ... and __Host-approve-auth-admin
// cookies for pending proof and admin sessions").
const adminCookieName = "__Host-approve-auth-admin"

func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAge.Seconds()),
	})
}

// clearCookie deletes a cookie the same way it was set (spec section 4):
// same name, Path=/, Secure, HttpOnly, SameSite=Lax, no Domain, and
// Max-Age=0.
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// singleCookieValue returns (value, true) if exactly one cookie named
// name is present, ("", true) if none is present, and ("", false) if
// more than one is present. Spec section 4: "Reject duplicate access-
// cookie names rather than picking the first or last value."
func singleCookieValue(r *http.Request, name string) (string, bool) {
	var found []string
	for _, c := range r.Cookies() {
		if c.Name == name {
			found = append(found, c.Value)
		}
	}
	switch len(found) {
	case 0:
		return "", true
	case 1:
		return found[0], true
	default:
		return "", false
	}
}
