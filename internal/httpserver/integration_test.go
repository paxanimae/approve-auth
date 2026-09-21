package httpserver_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/frid-iks/approve-auth/internal/authz"
	"github.com/frid-iks/approve-auth/internal/httpserver"
)

// --- test PKI helpers: a small self-signed CA + leaf issuer, entirely
// in-process (no mkcert -- that's for human-facing local dev trust, not a
// CI unit test; see docs/dev-environment.md). ---

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemEncodeKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func newSelfSignedCA(t *testing.T, cn string) (cert *x509.Certificate, key *ecdsa.PrivateKey, certPEM []byte) {
	t.Helper()
	key = generateKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA cert: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}
	return cert, key, pemEncodeCert(der)
}

func issueClientCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, serial int64) tls.Certificate {
	t.Helper()
	key := generateKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("issuing client cert for %s: %v", cn, err)
	}
	certPEM := pemEncodeCert(der)
	keyPEM := pemEncodeKey(t, key)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("loading issued client cert for %s: %v", cn, err)
	}
	return pair
}

func selfSignedServerCert(t *testing.T, cn string) (certFile, keyFile string) {
	t.Helper()
	key := generateKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating self-signed server cert: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "server-cert.pem")
	keyFile = filepath.Join(dir, "server-key.pem")
	if err := os.WriteFile(certFile, pemEncodeCert(der), 0o600); err != nil {
		t.Fatalf("writing server cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pemEncodeKey(t, key), 0o600); err != nil {
		t.Fatalf("writing server key: %v", err)
	}
	return certFile, keyFile
}

func writeCAFile(t *testing.T, certPEM []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca-cert.pem")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatalf("writing CA file: %v", err)
	}
	return path
}

// --- the actual integration test ---

func TestFourListeners_BindIndependentlyAndEnforceMTLS(t *testing.T) {
	serverCertFile, serverKeyFile := selfSignedServerCert(t, "auth.approve-auth.internal")

	trustedCA, trustedCAKey, trustedCAPEM := newSelfSignedCA(t, "test-trusted-ca")
	trustedCAFile := writeCAFile(t, trustedCAPEM)

	untrustedCA, untrustedCAKey, _ := newSelfSignedCA(t, "test-untrusted-ca")

	goodClientCert := issueClientCert(t, trustedCA, trustedCAKey, "traefik-client", 2)
	badIdentityClientCert := issueClientCert(t, trustedCA, trustedCAKey, "not-allowed-client", 3)
	untrustedClientCert := issueClientCert(t, untrustedCA, untrustedCAKey, "traefik-client", 4)

	authTLSConfig, err := httpserver.AuthTLSConfig(serverCertFile, serverKeyFile, trustedCAFile, []string{"traefik-client"})
	if err != nil {
		t.Fatalf("AuthTLSConfig: %v", err)
	}

	publicLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening (public): %v", err)
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening (admin): %v", err)
	}
	opsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening (ops): %v", err)
	}
	authRawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening (auth): %v", err)
	}
	authLn := tls.NewListener(authRawLn, authTLSConfig)

	t.Cleanup(func() {
		_ = publicLn.Close()
		_ = adminLn.Close()
		_ = opsLn.Close()
		_ = authRawLn.Close()
	})

	publicMux := httpserver.NewPublicMux(fakeEnroller{}, fakeDecider{decision: authz.Decision{Category: authz.CategoryAllow}}, time.Hour, time.Hour, time.Second, nil, "")
	go func() { _ = http.Serve(publicLn, publicMux) }()
	go func() {
		adminMux := httpserver.NewAdminMux(fakeAdminSessions{}, fakeAdminActions{}, fakeAdminReadStore{}, "admin.example.test", time.Hour, time.Hour, time.Hour, time.Hour, time.Hour, time.Hour, "test", "test")
		_ = http.Serve(adminLn, adminMux)
	}()
	go func() { _ = http.Serve(opsLn, httpserver.NewOpsMux(fakeReadyChecker{schemaReady: true})) }()
	authMux := httpserver.NewAuthMux(fakeDecider{decision: authz.Decision{Category: authz.CategoryAllow}}, time.Second)
	go func() { _ = http.Serve(authLn, authMux) }()

	t.Run("public listener serves plain HTTP", func(t *testing.T) {
		// /status is a real endpoint now (Milestone 3): with no pending
		// cookie it reports "not_requested" at 200, which is enough here
		// to prove the listener itself is up and routed -- the real
		// behavior has its own tests.
		resp, err := http.Get(fmt.Sprintf("http://%s/__approve-auth/status", publicLn.Addr()))
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("got status %d, want 200", resp.StatusCode)
		}
	})

	t.Run("admin listener serves plain HTTP", func(t *testing.T) {
		// The request's Host (127.0.0.1) never matches the fake "admin
		// .example.test" this test configured NewAdminMux with, so
		// requireAdminHost rejects it with 403 -- proving the listener
		// itself is up and the route matched, same intent as the public
		// listener check above. The real Host-match/session/CSRF behavior
		// has its own tests.
		resp, err := http.Get(fmt.Sprintf("http://%s/api/v1/me", adminLn.Addr()))
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("got status %d, want 403 (routed, rejected by the admin Host check)", resp.StatusCode)
		}
	})

	t.Run("ops listener serves plain HTTP liveness", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://%s/livez", opsLn.Addr()))
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("got status %d, want 200", resp.StatusCode)
		}
	})

	t.Run("auth listener rejects plain HTTP", func(t *testing.T) {
		// crypto/tls special-cases a plaintext HTTP request arriving where
		// it expected a TLS ClientHello: it writes back a plain 400
		// response instead of just closing the connection, so http.Get can
		// succeed at the transport level while still getting rejected.
		resp, err := http.Get(fmt.Sprintf("http://%s/auth", authRawLn.Addr()))
		if err != nil {
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode < 400 {
			t.Errorf("plain HTTP against the TLS-only auth listener: got status %d, want an error or a 4xx response", resp.StatusCode)
		}
	})

	t.Run("auth listener rejects TLS with no client certificate", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		_, err := client.Get(fmt.Sprintf("https://%s/auth", authLn.Addr()))
		if err == nil {
			t.Error("TLS with no client certificate: expected a handshake error, got nil")
		}
	})

	t.Run("auth listener rejects a client certificate from an untrusted CA", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{untrustedClientCert},
		}}}
		_, err := client.Get(fmt.Sprintf("https://%s/auth", authLn.Addr()))
		if err == nil {
			t.Error("TLS with an untrusted-CA client certificate: expected a handshake error, got nil")
		}
	})

	t.Run("auth listener rejects a trusted-CA certificate whose identity is not allowlisted", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{badIdentityClientCert},
		}}}
		_, err := client.Get(fmt.Sprintf("https://%s/auth", authLn.Addr()))
		if err == nil {
			t.Error("TLS with a non-allowlisted client identity: expected a handshake error, got nil")
		}
	})

	t.Run("auth listener accepts an allowlisted trusted client certificate", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{goodClientCert},
		}}}
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/auth", authLn.Addr()), nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		req.Header.Set("X-Forwarded-Host", "app.example.test")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Method", "GET")
		req.Header.Set("X-Forwarded-Uri", "/")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET with a valid, allowlisted client certificate: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("got status %d, want 204 (the fake decider always allows)", resp.StatusCode)
		}
	})

	t.Run("auth listener does not serve public routes", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{goodClientCert},
		}}}
		resp, err := client.Get(fmt.Sprintf("https://%s/__approve-auth/status", authLn.Addr()))
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("got status %d, want 404 (public route must not exist on the auth listener)", resp.StatusCode)
		}
	})
}
