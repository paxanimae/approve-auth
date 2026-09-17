package authz

// AuthRequest is the metadata Traefik's ForwardAuth call carries (spec
// section 6): the forwarded host/method/URI, the client address chain,
// and whatever cookie value was presented.
type AuthRequest struct {
	Host           string
	Method         string
	URI            string
	ClientAddr     string
	CookieValue    string
	NavigationHint bool // GET with Sec-Fetch-Mode=navigate, Sec-Fetch-Dest=document
}

// Decision is the outcome of the authoritative check in spec section 3.
type Decision struct {
	Allow  bool
	Reason string
}
