// Command mock-oidc is a small, real (not mocked-out) OIDC Authorization
// Code provider for local development and the real-Traefik integration
// stack: it serves genuine signed JWTs from real discovery/JWKS/authorize/
// token endpoints, exactly like internal/oidc's own test provider
// (internal/oidc/client_test.go), but as a long-running service so the
// full admin console can be exercised through a real browser round trip
// against deploy/dev/docker-compose.yml.
//
// It auto-approves every /authorize request for one hardcoded identity --
// there is no login form, no user database, and no production use for
// this binary. It is never built into the production Docker image.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	addr := flag.String("addr", ":8090", "listen address")
	issuer := flag.String("issuer", "", "this provider's issuer URL, reachable by whatever calls discovery/jwks/token (typically an internal, backend-only address) (required)")
	authorizeURL := flag.String("authorize-url", "", "the browser-reachable URL for the authorization endpoint, if different from <issuer>/authorize (e.g. reachable only via a reverse proxy the backend doesn't need)")
	clientID := flag.String("client-id", "dev-placeholder", "the only client ID this provider accepts")
	subject := flag.String("subject", "dev-admin", "the OIDC subject every login returns")
	displayName := flag.String("name", "Dev Admin", "the display name every login returns")
	groups := flag.String("groups", "grp-admins", "comma-separated groups claim every login returns")
	flag.Parse()

	if *issuer == "" {
		return fmt.Errorf("-issuer is required")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating signing key: %w", err)
	}

	resolvedAuthorizeURL := *authorizeURL
	if resolvedAuthorizeURL == "" {
		resolvedAuthorizeURL = strings.TrimSuffix(*issuer, "/") + "/authorize"
	}

	p := &provider{
		issuer: strings.TrimSuffix(*issuer, "/"), authorizeURL: resolvedAuthorizeURL, key: key, kid: "mock-oidc",
		clientID: *clientID, subject: *subject, displayName: *displayName,
		groups: strings.Split(*groups, ","),
		codes:  map[string]codeState{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks.json", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)

	log.Printf("mock-oidc listening on %s (issuer=%s, subject=%s, groups=%v)", *addr, p.issuer, p.subject, p.groups)
	return http.ListenAndServe(*addr, mux)
}

type codeState struct {
	nonce       string
	redirectURI string
}

type provider struct {
	issuer       string
	authorizeURL string
	key          *rsa.PrivateKey
	kid          string
	clientID     string
	subject      string
	displayName  string
	groups       []string

	mu    sync.Mutex
	codes map[string]codeState
}

func (p *provider) discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.authorizeURL,
		"token_endpoint":                        p.issuer + "/token",
		"jwks_uri":                              p.issuer + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *provider) jwks(w http.ResponseWriter, _ *http.Request) {
	jwk := jose.JSONWebKey{Key: &p.key.PublicKey, KeyID: p.kid, Algorithm: "RS256", Use: "sig"}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

// authorize auto-approves unconditionally -- there is no user to prompt,
// this exists so a real browser redirect round trip has somewhere to
// land and come back from.
func (p *provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	code := randomToken()
	p.mu.Lock()
	p.codes[code] = codeState{nonce: q.Get("nonce"), redirectURI: redirectURI}
	p.mu.Unlock()

	dest, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	values := dest.Query()
	values.Set("code", code)
	values.Set("state", state)
	dest.RawQuery = values.Encode()

	http.Redirect(w, r, dest.String(), http.StatusFound)
}

// token exchanges a single-use code for a signed ID token. PKCE
// verification is intentionally skipped: this provider is the one
// system under our own control in this exchange, so there is nothing
// to protect it from -- the code under test is internal/oidc's client
// side of the exchange, not IdP-side PKCE enforcement.
func (p *provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("code")

	p.mu.Lock()
	state, ok := p.codes[code]
	if ok {
		delete(p.codes, code)
	}
	p.mu.Unlock()
	if !ok {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	now := time.Now()
	claims := map[string]any{
		"iss":    p.issuer,
		"sub":    p.subject,
		"aud":    p.clientID,
		"exp":    now.Add(time.Hour).Unix(),
		"iat":    now.Unix(),
		"nonce":  state.nonce,
		"name":   p.displayName,
		"groups": p.groups,
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", p.kid))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "mock-access-token",
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read failing means the OS entropy source is broken;
		// nothing meaningful to recover to.
		fmt.Fprintln(os.Stderr, "mock-oidc: reading random bytes:", err)
		os.Exit(1)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
