package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/frid-iks/traefik-manual-proxy/internal/oidc"
)

// mockProvider is a minimal, real OIDC provider (discovery + JWKS + token
// endpoint, all serving genuine signed JWTs) for testing internal/oidc's
// actual verification logic -- go-oidc's signature/issuer/audience/expiry
// checks run for real against this, the same as they would against a
// real IdP; only network/browser-redirect mechanics are skipped, since
// Exchange never calls /authorize at all (that's the browser's job).
type mockProvider struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	clientID string
	codes    map[string]map[string]any
}

func newMockProvider(t *testing.T, clientID string) *mockProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	mp := &mockProvider{key: key, kid: "test-key", clientID: clientID, codes: map[string]map[string]any{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", mp.discovery)
	mux.HandleFunc("/keys", mp.jwks)
	mux.HandleFunc("/token", mp.token)
	mp.srv = httptest.NewServer(mux)
	t.Cleanup(mp.srv.Close)
	return mp
}

func (mp *mockProvider) issuer() string { return mp.srv.URL }

func (mp *mockProvider) discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                mp.issuer(),
		"authorization_endpoint":                mp.issuer() + "/authorize",
		"token_endpoint":                        mp.issuer() + "/token",
		"jwks_uri":                              mp.issuer() + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (mp *mockProvider) jwks(w http.ResponseWriter, r *http.Request) {
	jwk := josejwt.JSONWebKey{Key: &mp.key.PublicKey, KeyID: mp.kid, Algorithm: "RS256", Use: "sig"}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(josejwt.JSONWebKeySet{Keys: []josejwt.JSONWebKey{jwk}})
}

// registerCode pre-seeds a code the test's call to Exchange will present
// -- standing in for what a real browser round trip through /authorize
// would have produced.
func (mp *mockProvider) registerCode(code string, claims map[string]any) {
	mp.codes[code] = claims
}

func (mp *mockProvider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("code")
	claims, ok := mp.codes[code]
	if !ok {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	now := time.Now()
	allClaims := map[string]any{
		"iss": mp.issuer(),
		"aud": mp.clientID,
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
	for k, v := range claims {
		allClaims[k] = v
	}

	signer, err := josejwt.NewSigner(josejwt.SigningKey{Algorithm: josejwt.RS256, Key: mp.key}, (&josejwt.SignerOptions{}).WithHeader("kid", mp.kid))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idToken, err := jwt.Signed(signer).Claims(allClaims).Serialize()
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

func TestClient_Exchange_Success(t *testing.T) {
	ctx := context.Background()
	mp := newMockProvider(t, "test-client-id")
	client, err := oidc.NewClient(ctx, mp.issuer(), "test-client-id", "test-client-secret", "https://admin.example.test/auth/callback")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	mp.registerCode("good-code", map[string]any{
		"sub":    "user-123",
		"name":   "Ada Admin",
		"nonce":  "expected-nonce",
		"groups": []string{"grp-admins"},
	})

	identity, err := client.Exchange(ctx, "good-code", "verifier-doesnt-matter-for-mock-token-endpoint", "expected-nonce")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Issuer != mp.issuer() {
		t.Errorf("Issuer = %q, want %q", identity.Issuer, mp.issuer())
	}
	if identity.Subject != "user-123" {
		t.Errorf("Subject = %q, want user-123", identity.Subject)
	}
	if identity.DisplayName != "Ada Admin" {
		t.Errorf("DisplayName = %q, want Ada Admin", identity.DisplayName)
	}
	if len(identity.Groups) != 1 || identity.Groups[0] != "grp-admins" {
		t.Errorf("Groups = %v, want [grp-admins]", identity.Groups)
	}
}

func TestClient_Exchange_RejectsWrongNonce(t *testing.T) {
	ctx := context.Background()
	mp := newMockProvider(t, "test-client-id")
	client, err := oidc.NewClient(ctx, mp.issuer(), "test-client-id", "test-client-secret", "https://admin.example.test/auth/callback")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	mp.registerCode("code-1", map[string]any{"sub": "user-123", "nonce": "actual-nonce"})

	_, err = client.Exchange(ctx, "code-1", "verifier", "different-nonce")
	if err == nil {
		t.Fatal("Exchange with a mismatched nonce: expected an error, got nil")
	}
}

func TestClient_Exchange_RejectsWrongAudience(t *testing.T) {
	ctx := context.Background()
	mp := newMockProvider(t, "test-client-id")
	client, err := oidc.NewClient(ctx, mp.issuer(), "test-client-id", "test-client-secret", "https://admin.example.test/auth/callback")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// The mock's /token endpoint sets aud to mp.clientID unconditionally,
	// so simulate a wrong-audience token by registering a code whose
	// claims override "aud" directly.
	mp.registerCode("code-1", map[string]any{"sub": "user-123", "nonce": "n", "aud": "some-other-client"})

	_, err = client.Exchange(ctx, "code-1", "verifier", "n")
	if err == nil {
		t.Fatal("Exchange with a token for a different audience: expected an error, got nil")
	}
}

func TestClient_AuthURL_ContainsPKCEParams(t *testing.T) {
	ctx := context.Background()
	mp := newMockProvider(t, "test-client-id")
	client, err := oidc.NewClient(ctx, mp.issuer(), "test-client-id", "test-client-secret", "https://admin.example.test/auth/callback")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	u := client.AuthURL("state-123", "nonce-456", "challenge-789")
	for _, want := range []string{"state=state-123", "nonce=nonce-456", "code_challenge=challenge-789", "code_challenge_method=S256"} {
		if !strings.Contains(u, want) {
			t.Errorf("AuthURL = %q, expected it to contain %q", u, want)
		}
	}
}
