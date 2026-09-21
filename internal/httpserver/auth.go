package httpserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/paxanimae/approve-auth/internal/authz"
	"github.com/paxanimae/approve-auth/internal/metrics"
)

// stripPort removes a ":port" suffix from a Host-style value, lowercasing
// the result. Applications are registered by hostname alone (spec
// section 3 rejects non-443 ports at registration), and in a real
// deployment neither the Public listener's Host header nor the
// Authorization listener's X-Forwarded-Host ever carries a port at all
// -- browsers only include one for a non-default port, and production
// only ever runs on 443. Both listeners that resolve "which application
// does this request belong to" share this helper so they stay
// consistent with each other; without it, a dev/test deployment on a
// non-standard port (this project's own dev stack uses :18443 to avoid
// colliding with other local services) enrolls a browser against the
// port-stripped hostname while the Authorization listener's decision
// checks the port-inclusive one, so a freshly claimed credential is
// never recognized as belonging to the same application.
func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

// Decider is the authz.Service surface the /auth handler needs. Defined
// here (not just *authz.Service) so httpserver_test.go can substitute a
// fake and test the header-parsing/response-mapping contract without a
// database underneath authz too.
type Decider interface {
	Decide(ctx context.Context, req authz.AuthRequest) (authz.Decision, error)
}

// singleHeaderValue requires the header to appear exactly once -- a
// repeated header (rather than a single comma-joined value) is treated
// as malformed, matching the strict single-value requirement spec
// section 6 places on X-Forwarded-Host in particular.
func singleHeaderValue(r *http.Request, name string) (string, bool) {
	values := r.Header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	return strings.TrimSpace(values[0]), true
}

func headerValue(r *http.Request, name string) string {
	return r.Header.Get(name)
}

// parsedAuthRequest is parseAuthRequest's result: either a well-formed
// authz.AuthRequest, or Malformed=true, meaning the caller must respond
// 400 without ever reaching the decider (spec section 6: "Malformed
// metadata/cookie" -> 400, no redirect).
type parsedAuthRequest struct {
	req       authz.AuthRequest
	rawHost   string // X-Forwarded-Host verbatim (port included, if any) -- see requestPageRedirectLocation
	malformed bool
}

func parseAuthRequest(r *http.Request) parsedAuthRequest {
	host, ok := singleHeaderValue(r, "X-Forwarded-Host")
	if !ok || host == "" || strings.ContainsAny(host, " \t/\\,") {
		return parsedAuthRequest{malformed: true}
	}
	proto, ok := singleHeaderValue(r, "X-Forwarded-Proto")
	if !ok || !strings.EqualFold(proto, "https") {
		return parsedAuthRequest{malformed: true}
	}
	method, ok := singleHeaderValue(r, "X-Forwarded-Method")
	if !ok || method == "" {
		return parsedAuthRequest{malformed: true}
	}
	uri, ok := singleHeaderValue(r, "X-Forwarded-Uri")
	if !ok || !strings.HasPrefix(uri, "/") {
		return parsedAuthRequest{malformed: true}
	}

	cookieValue, ok := singleCookieValue(r, accessCookieName)
	if !ok {
		return parsedAuthRequest{malformed: true}
	}

	return parsedAuthRequest{
		rawHost: host,
		req: authz.AuthRequest{
			Host:           stripPort(host),
			Method:         strings.ToUpper(method),
			URI:            uri,
			ClientAddr:     clientAddr(r),
			UserAgent:      headerValue(r, "User-Agent"),
			CookieValue:    cookieValue,
			NavigationHint: isNavigation(r, method),
		},
	}
}

// isNavigation classifies the original request per spec section 6: a GET
// with Sec-Fetch-Mode=navigate and Sec-Fetch-Dest=document, or -- for
// older browsers lacking Fetch Metadata -- a GET that accepts text/html.
func isNavigation(r *http.Request, method string) bool {
	if !strings.EqualFold(method, "GET") {
		return false
	}
	mode := headerValue(r, "Sec-Fetch-Mode")
	dest := headerValue(r, "Sec-Fetch-Dest")
	if mode != "" || dest != "" {
		return strings.EqualFold(mode, "navigate") && strings.EqualFold(dest, "document")
	}
	return strings.Contains(headerValue(r, "Accept"), "text/html")
}

// clientAddr takes the last hop of X-Forwarded-For when present. Traefik
// always adds this on the Authorization listener regardless of
// authRequestHeaders (it's Traefik-generated metadata, not a copied
// original header) -- full multi-hop CIDR-chain validation isn't needed
// here: this listener requires mTLS (see AuthTLSConfig), so Traefik
// itself is already the sole, cryptographically-verified caller, unlike
// the Public listener (see publicClientIP below, endpoint-review.md F2).
func clientAddr(r *http.Request) string {
	if xff := headerValue(r, "X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return r.RemoteAddr
}

// parseTrustedCIDRs parses config-validated CIDR strings into *net.IPNet.
// config.Config.Validate already guarantees every configured entry
// parses; a bad entry here (e.g. an empty/malformed value reaching this
// code some other way, such as a test) is simply skipped rather than
// panicking -- an unparseable "trusted" CIDR trusts nothing, which is
// the fail-closed direction.
func parseTrustedCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, raw := range cidrs {
		if _, ipnet, err := net.ParseCIDR(raw); err == nil {
			out = append(out, ipnet)
		}
	}
	return out
}

// peerIsTrusted reports whether remoteAddr's host (a Go net/http
// RemoteAddr, "host:port") falls inside one of trusted's CIDR blocks.
func peerIsTrusted(remoteAddr string, trusted []*net.IPNet) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// publicClientIP resolves the caller's IP for the Public listener's own
// rate-limiting and audit purposes (endpoint-review.md F2). Unlike
// clientAddr above, the Public listener can be reached directly by
// anyone, not only via Traefik -- X-Forwarded-For is trusted only when
// the immediate TCP peer (r.RemoteAddr) is itself inside
// TrustedTraefikCIDRs; otherwise it's ignored entirely and the real TCP
// peer address is used, so a caller reaching this listener directly
// cannot forge whatever rate-limit/audit identity it likes by sending
// its own X-Forwarded-For header.
func publicClientIP(r *http.Request, trusted []*net.IPNet) string {
	if peerIsTrusted(r.RemoteAddr, trusted) {
		return clientAddr(r)
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	return host
}

// requestPageRedirectLocation builds the same-host reserved-path
// enrollment redirect (spec section 5, step 1). host must be the
// browser's own X-Forwarded-Host verbatim (port included, if any), not
// the port-stripped value used for application lookup -- this is an
// absolute URL the browser has to actually follow back to wherever it's
// currently connected, and a dev/test deployment on a non-standard port
// (this project's own dev stack uses :18443) would otherwise redirect
// the browser to the default port 443, which nothing is listening on.
// A real deployment only ever runs on 443, where this makes no
// difference either way.
func requestPageRedirectLocation(host, uri string) string {
	return fmt.Sprintf("https://%s/__approve-auth/request?return_to=%s", host, url.QueryEscape(uri))
}

// NewAuthMux serves the ForwardAuth decision endpoint (spec section 6) on
// the Authorization listener only. The listener itself always requires
// mTLS -- see AuthTLSConfig -- independent of what this handler decides.
// decisionTimeout bounds Decide (spec section 14's AUTH_DECISION_TIMEOUT):
// exceeding it is treated the same as a database error -- 503, fail
// closed, never fall back to allow.
func NewAuthMux(decider Decider, decisionTimeout time.Duration) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", authHandler(decider, decisionTimeout))
	return mux
}

func authHandler(decider Decider, decisionTimeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() { metrics.AuthDecisionDuration.Observe(time.Since(start).Seconds()) }()

		parsed := parseAuthRequest(r)
		if parsed.malformed {
			metrics.AuthDecisions.WithLabelValues("malformed", "malformed_request").Inc()
			writeAPIError(w, http.StatusBadRequest, "malformed_request", "malformed forwarded request metadata or cookie")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), decisionTimeout)
		defer cancel()
		decision, err := decider.Decide(ctx, parsed.req)
		if err != nil {
			metrics.AuthDecisions.WithLabelValues("error", "decision_unavailable").Inc()
			w.Header().Set("Retry-After", "5")
			writeAPIError(w, http.StatusServiceUnavailable, "decision_unavailable", "authorization decision temporarily unavailable")
			return
		}
		metrics.AuthDecisions.WithLabelValues(decision.Category.String(), decision.Reason).Inc()

		switch decision.Category {
		case authz.CategoryAllow:
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
		case authz.CategoryUnknownHost:
			writeAPIError(w, http.StatusForbidden, "unknown_host", "this host is not protected by this service")
		case authz.CategoryRevokedOrDisabled:
			writeAPIError(w, http.StatusForbidden, "access_denied", "access has been revoked or this application is disabled")
		case authz.CategoryMissingOrInvalidCredential:
			if parsed.req.NavigationHint {
				w.Header().Set("Location", requestPageRedirectLocation(parsed.rawHost, parsed.req.URI))
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusSeeOther)
			} else {
				writeAPIError(w, http.StatusUnauthorized, "credential_required", "a valid access credential is required")
			}
		default:
			writeAPIError(w, http.StatusForbidden, "access_denied", "access denied")
		}
	}
}
