package authz

// AuthRequest is the metadata Traefik's ForwardAuth call carries (spec
// section 6), already interpreted by internal/httpserver from the raw
// forwarded headers -- this package makes the business decision, it
// doesn't parse HTTP.
type AuthRequest struct {
	Host           string
	Method         string
	URI            string
	ClientAddr     string
	UserAgent      string
	CookieValue    string // "" means no access cookie was presented
	NavigationHint bool   // GET with Sec-Fetch-Mode=navigate, Sec-Fetch-Dest=document (or the no-Fetch-Metadata fallback)
}

// Category is the HTTP-response bucket from spec section 6's decision
// table. Multiple internal Reasons collapse into the same Category --
// the table only distinguishes these four outcomes (plus the 400/503
// cases internal/httpserver handles before/around a Decide call: malformed
// request metadata never reaches Decide, and a DB error is a 503, not a
// Decision at all).
type Category int

const (
	CategoryAllow Category = iota
	CategoryUnknownHost
	CategoryMissingOrInvalidCredential
	CategoryRevokedOrDisabled
)

// Decision is the outcome of the authoritative check (spec section 3).
type Decision struct {
	Category Category
	Reason   string // human-readable, for logs -- never shown to the browser
}
