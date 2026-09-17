package httpserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	webadmin "github.com/frid-iks/traefik-manual-proxy/web/admin"
	webpublic "github.com/frid-iks/traefik-manual-proxy/web/public"
)

type apiError struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

// securityHeaders applies spec section 11 control 4 to every response
// on a browser-facing listener: a restrictive CSP (default-src 'none',
// same-origin only for the asset types this service actually serves,
// no framing), plus Referrer-Policy and X-Content-Type-Options. Wrapping
// the whole mux rather than each handler is safe here -- unlike a
// gating middleware, this only ever adds headers and always calls next,
// so it can't change any response's status code (in particular, the
// cross-listener-isolation exit gate's 404s are unaffected).
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// writeAPIError writes the structured error body every control-plane
// response uses (spec section 9): { "error": { code, message,
// request_id } }, with Cache-Control: no-store since nothing on this
// path may be cached by an intermediary (spec section 6).
func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	var body apiError
	body.Error.Code = code
	body.Error.Message = message
	body.Error.RequestID = uuid.New().String()
	_ = json.NewEncoder(w).Encode(body)
}

// NewPublicMux serves the same-host reserved-path endpoints (spec
// section 9) on the Public listener only. Traefik's reserved-path
// router points here; the protected application router never does.
//
// requestTTL bounds the pending-proof cookie's lifetime (spec section
// 14's REQUEST_TTL); credentialCookieMaxAge is the access cookie's fixed
// browser lifetime (spec section 4: 365 days, bounded separately by the
// credential's own absolute_expires_at, which internal/authz enforces);
// decisionTimeout bounds the /session check the same way it bounds
// /auth on the Authorization listener.
func NewPublicMux(enroller Enroller, decider Decider, requestTTL, credentialCookieMaxAge, decisionTimeout time.Duration) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /__manual-approval/request", requestPageHandler(enroller, requestTTL))
	mux.HandleFunc("POST /__manual-approval/requests", submitRequestHandler(enroller))
	mux.HandleFunc("GET /__manual-approval/waiting", waitingPageHandler(enroller))
	mux.HandleFunc("GET /__manual-approval/status", statusHandler(enroller))
	mux.HandleFunc("POST /__manual-approval/cancel", cancelHandler(enroller))
	mux.HandleFunc("POST /__manual-approval/claim", claimHandler(enroller, credentialCookieMaxAge))
	mux.HandleFunc("GET /__manual-approval/session", sessionHandler(decider, decisionTimeout))
	mux.HandleFunc("POST /__manual-approval/ack", ackHandler(enroller))
	mux.HandleFunc("POST /__manual-approval/logout", logoutHandler(enroller))
	mux.Handle("GET /__manual-approval/assets/", http.StripPrefix("/__manual-approval/assets/", publicAssetsHandler()))

	wrapped := http.NewServeMux()
	wrapped.Handle("/", securityHeaders(mux))
	return wrapped
}

// publicAssetsHandler serves the embedded, locally bundled public-page
// assets only (spec section 9: "Locally bundled public-page assets
// only") -- no filesystem access outside web/public/assets.
func publicAssetsHandler() http.Handler {
	sub, err := fs.Sub(webpublic.Assets, "assets")
	if err != nil {
		panic(err) // embedded at build time; cannot fail at runtime
	}
	return http.FileServerFS(sub)
}

// NewAdminMux serves OIDC login/callback/logout and the /api/v1 admin API
// (spec section 9) on the Admin listener only. adminHost is the
// configured admin hostname (spec section 9: "Verify admin Host equals
// configured admin hostname"); sessionCookieMaxAge bounds the admin
// session cookie's browser lifetime, matching AdminAbsoluteTTL so the
// cookie never outlives the session it names; expiringSoonWindow and
// recentWindow back GET /overview's counts.
func NewAdminMux(sessions AdminSessions, actions AdminActions, readStore AdminReadStore, adminHost string, sessionCookieMaxAge, expiringSoonWindow, recentWindow time.Duration) *http.ServeMux {
	mux := http.NewServeMux()

	// Every route below checks the admin Host first (spec section 9).
	withHost := func(h http.HandlerFunc) http.HandlerFunc { return requireAdminHost(adminHost, h) }
	// Any live session, either role (spec section 9: "viewer reads
	// operational state and audit; administrator also mutates").
	authed := func(h http.HandlerFunc) http.HandlerFunc { return withHost(requireAdminSession(sessions, h)) }
	// A valid CSRF token, but no role restriction -- logout is a
	// mutation any authenticated admin (viewer or administrator) may
	// perform on their own session (spec section 9: "CSRF protection for
	// every mutation, including logout").
	csrfProtected := func(h http.HandlerFunc) http.HandlerFunc {
		return withHost(requireAdminSession(sessions, requireAdminCSRF(h)))
	}
	// Administrator role plus a valid CSRF token -- every other mutation.
	mutating := func(h http.HandlerFunc) http.HandlerFunc {
		return withHost(requireAdminSession(sessions, requireAdministrator(requireAdminCSRF(h))))
	}

	mux.HandleFunc("GET /auth/login", withHost(adminLoginHandler(sessions)))
	mux.HandleFunc("GET /auth/callback", withHost(adminCallbackHandler(sessions, sessionCookieMaxAge)))
	mux.HandleFunc("POST /auth/logout", csrfProtected(adminLogoutHandler(sessions)))
	mux.HandleFunc("GET /api/v1/me", authed(adminMeHandler()))

	mux.HandleFunc("GET /api/v1/overview", authed(overviewHandler(readStore, expiringSoonWindow, recentWindow)))

	mux.HandleFunc("GET /api/v1/applications", authed(listApplicationsHandler(readStore)))
	mux.HandleFunc("POST /api/v1/applications", mutating(createApplicationHandler(actions)))
	mux.HandleFunc("GET /api/v1/applications/{id}", authed(getApplicationHandler(readStore)))
	mux.HandleFunc("PATCH /api/v1/applications/{id}", mutating(updateApplicationHandler(actions)))
	mux.HandleFunc("POST /api/v1/applications/{id}/disable", mutating(disableApplicationHandler(actions)))
	mux.HandleFunc("POST /api/v1/applications/{id}/enable", mutating(enableApplicationHandler(actions)))

	mux.HandleFunc("GET /api/v1/requests", authed(listRequestsHandler(readStore)))
	mux.HandleFunc("GET /api/v1/requests/{id}", authed(getRequestHandler(readStore)))
	mux.HandleFunc("POST /api/v1/requests/{id}/approve", mutating(approveRequestHandler(actions)))
	mux.HandleFunc("POST /api/v1/requests/{id}/deny", mutating(denyRequestHandler(actions)))

	mux.HandleFunc("GET /api/v1/authorizations", authed(listAuthorizationsHandler(readStore)))
	mux.HandleFunc("GET /api/v1/authorizations/{id}", authed(getAuthorizationHandler(readStore)))
	mux.HandleFunc("POST /api/v1/authorizations/{id}/renew", mutating(renewAuthorizationHandler(actions)))
	mux.HandleFunc("POST /api/v1/authorizations/{id}/revoke", mutating(revokeAuthorizationHandler(actions)))
	mux.HandleFunc("POST /api/v1/authorizations/bulk-renew", mutating(bulkRenewHandler(actions, readStore)))
	mux.HandleFunc("POST /api/v1/authorizations/bulk-revoke", mutating(bulkRevokeHandler(actions)))

	mux.HandleFunc("GET /api/v1/audit-events", authed(listAuditEventsHandler(readStore)))
	mux.HandleFunc("GET /api/v1/audit-events/export", authed(exportAuditEventsHandler(readStore)))

	// The console itself: everything not matched above (spec section 2:
	// "Serve compiled admin assets from the Go binary"). Deliberately not
	// behind withHost: it's a static, unauthenticated shell with no
	// secrets in it (same trust level as the public listener's own
	// asset handler) -- every actual API call it makes is separately
	// Host-checked, session-checked, and (for mutations) CSRF-checked.
	// This also keeps an unmatched path here a plain 404 from the file
	// server, not a Host-check 403, for the cross-listener isolation
	// exit gate.
	mux.HandleFunc("/", adminConsoleHandler())

	wrapped := http.NewServeMux()
	wrapped.Handle("/", securityHeaders(mux))
	return wrapped
}

// adminConsoleHandler serves the embedded, built Svelte admin console:
// index.html at "/", its hashed asset files under "/assets/" (safe to
// cache indefinitely -- Vite's content hash changes the filename on any
// change), and a plain 404 for anything else, exactly like an ordinary
// static file server would.
func adminConsoleHandler() http.HandlerFunc {
	sub, err := fs.Sub(webadmin.Dist, "dist")
	if err != nil {
		panic(err) // embedded at build time; cannot fail at runtime
	}
	fileServer := http.FileServerFS(sub)
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		fileServer.ServeHTTP(w, r)
	}
}

// ReadyChecker is the internal/store.DB surface GET /readyz needs.
type ReadyChecker interface {
	Ping(ctx context.Context) error
	SchemaReady(ctx context.Context) (bool, error)
}

// NewOpsMux serves process-health and metrics endpoints on the Ops
// listener only (spec section 2: "Internal monitoring network only";
// spec section 15: "Restrict metrics to operations access").
func NewOpsMux(ready ReadyChecker) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
	})
	// Readiness checks database connectivity and schema compatibility
	// (spec section 13) -- required secrets and listener initialization
	// are checked at startup, before any listener including this one
	// ever binds, so a replica answering at all already satisfies those.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if err := ready.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		schemaReady, err := ready.SchemaReady(r.Context())
		if err != nil || !schemaReady {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("GET /metrics", promhttp.Handler())
	return mux
}

// AuthTLSConfig builds the TLS configuration for the Authorization
// listener: it always requires and verifies a client certificate (spec
// section 2: "Traefik only, mTLS required"), and further restricts callers
// to the explicit identity allowlist from AUTH_ALLOWED_CLIENT_IDENTITIES --
// mTLS alone does not make an arbitrary client trustworthy.
func AuthTLSConfig(certFile, keyFile, clientCAFile string, allowedClientIdentities []string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("httpserver: loading auth listener certificate: %w", err)
	}

	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("httpserver: reading auth client CA: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("httpserver: no certificates found in %s", clientCAFile)
	}

	allowed := make(map[string]bool, len(allowedClientIdentities))
	for _, id := range allowedClientIdentities {
		allowed[id] = true
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
		VerifyPeerCertificate: func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, chain := range verifiedChains {
				if len(chain) == 0 {
					continue
				}
				leaf := chain[0]
				if allowed[leaf.Subject.CommonName] {
					return nil
				}
				for _, name := range leaf.DNSNames {
					if allowed[name] {
						return nil
					}
				}
			}
			return fmt.Errorf("httpserver: client certificate identity not in AUTH_ALLOWED_CLIENT_IDENTITIES")
		},
	}, nil
}
