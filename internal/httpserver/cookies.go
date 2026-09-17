package httpserver

import "net/http"

// accessCookieName is fixed across every protected application (spec
// section 4): a single __Host- prefixed name, so browsers enforce
// Secure+Path=/+no-Domain on it themselves, and the server additionally
// binds each credential to its own application (see internal/authz).
const accessCookieName = "__Host-manual-proxy"

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
