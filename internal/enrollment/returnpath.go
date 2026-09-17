package enrollment

import (
	"net/url"
	"strings"
)

const maxReturnPathBytes = 2048

// validateReturnPath implements spec section 5's "Return targets" rule
// exactly: an origin-relative path beginning with exactly one `/`, plus
// optional query, at most 2048 bytes, rejecting schemes, authorities,
// `//`, backslashes, control characters, and encoded forms that become
// any of those after decoding -- falling back to "/" on any violation
// rather than erroring, since this is validated on entry and again
// before every redirect that uses it.
func validateReturnPath(raw string) string {
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

	// A scheme or authority sneaking in (e.g. "/\t/evil.example" decoding
	// to something url.Parse treats as absolute) is caught by requiring
	// the parsed result to still carry no Scheme/Host/Opaque/User.
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Opaque != "" || u.User != nil {
		return fallback
	}

	return raw
}
