package httpserver

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	webpublic "github.com/frid-iks/traefik-manual-proxy/web/public"
)

type apiError struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
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

// writeNotImplemented is the standard response for every route this
// milestone declares but doesn't implement: it exists on the right
// listener (that's the part M1 tests), but the business logic behind it
// is a later milestone.
func writeNotImplemented(w http.ResponseWriter, message string) {
	writeAPIError(w, http.StatusNotImplemented, "not_implemented", message)
}

func stub(message string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeNotImplemented(w, message)
	}
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

	return mux
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
// (spec section 9) on the Admin listener only.
func NewAdminMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /auth/login", stub("admin OIDC login: Milestone 4"))
	mux.HandleFunc("GET /auth/callback", stub("admin OIDC callback: Milestone 4"))
	mux.HandleFunc("POST /auth/logout", stub("admin logout: Milestone 4"))
	mux.HandleFunc("GET /api/v1/me", stub("admin identity: Milestone 4"))

	mux.HandleFunc("GET /api/v1/overview", stub("overview counts: Milestone 4"))

	mux.HandleFunc("GET /api/v1/applications", stub("list applications: Milestone 4"))
	mux.HandleFunc("POST /api/v1/applications", stub("register application: Milestone 4"))
	mux.HandleFunc("GET /api/v1/applications/{id}", stub("application detail: Milestone 4"))
	mux.HandleFunc("PATCH /api/v1/applications/{id}", stub("update application: Milestone 4"))
	mux.HandleFunc("POST /api/v1/applications/{id}/disable", stub("disable application: Milestone 4"))
	mux.HandleFunc("POST /api/v1/applications/{id}/enable", stub("enable application: Milestone 4"))

	mux.HandleFunc("GET /api/v1/requests", stub("list requests: Milestone 4"))
	mux.HandleFunc("GET /api/v1/requests/{id}", stub("request detail: Milestone 4"))
	mux.HandleFunc("POST /api/v1/requests/{id}/approve", stub("approve request: Milestone 3"))
	mux.HandleFunc("POST /api/v1/requests/{id}/deny", stub("deny request: Milestone 3"))

	mux.HandleFunc("GET /api/v1/authorizations", stub("list authorizations: Milestone 4"))
	mux.HandleFunc("GET /api/v1/authorizations/{id}", stub("authorization detail: Milestone 4"))
	mux.HandleFunc("POST /api/v1/authorizations/{id}/renew", stub("renew authorization: Milestone 3"))
	mux.HandleFunc("POST /api/v1/authorizations/{id}/revoke", stub("revoke authorization: Milestone 3"))
	mux.HandleFunc("POST /api/v1/authorizations/bulk-renew", stub("bulk renew: Milestone 4"))
	mux.HandleFunc("POST /api/v1/authorizations/bulk-revoke", stub("bulk revoke: Milestone 4"))

	mux.HandleFunc("GET /api/v1/audit-events", stub("list audit events: Milestone 4"))
	mux.HandleFunc("GET /api/v1/audit-events/export", stub("export audit events: Milestone 4"))

	return mux
}

// NewOpsMux serves process-health endpoints on the Ops listener only.
// Liveness only in this milestone: readiness needs real schema/dependency
// checks that don't exist until the milestone that adds repository code.
func NewOpsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
	})
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
