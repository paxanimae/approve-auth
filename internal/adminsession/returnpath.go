package adminsession

import (
	"net/url"
	"strings"
)

const maxReturnPathBytes = 2048

// validateAdminReturnPath applies the same rule spec section 5 states
// for the enrollment flow's return targets (an origin-relative path, one
// leading slash, no scheme/authority/backslash/control chars, decoded-
// form re-checked) to where a completed admin login lands -- duplicated
// from internal/enrollment/returnpath.go rather than shared, since it's
// a small pure function and the two packages have no other reason to
// depend on each other.
func validateAdminReturnPath(raw string) string {
	const fallback = "/"
	if raw == "" || len(raw) > maxReturnPathBytes {
		return fallback
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return fallback
	}
	if strings.ContainsAny(raw, "\\") {
		return fallback
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return fallback
		}
	}

	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return fallback
	}
	if strings.HasPrefix(decoded, "//") || strings.ContainsAny(decoded, "\\") {
		return fallback
	}
	for _, r := range decoded {
		if r < 0x20 || r == 0x7f {
			return fallback
		}
	}

	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Opaque != "" || u.User != nil {
		return fallback
	}

	return raw
}
