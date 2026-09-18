package store_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/frid-iks/traefik-manual-proxy/internal/store"
)

func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parsing UUID %q: %v", s, err)
	}
	return id
}

// testDatabaseURL is a superuser-capable connection string (e.g. the
// docker-compose dev "postgres" role), used to run migrations. Individual
// tests that need to act as a specific application role derive a new
// connection string from it via connString.
var testDatabaseURL string

func TestMain(m *testing.M) {
	testDatabaseURL = os.Getenv("TEST_DATABASE_URL")
	if testDatabaseURL != "" {
		_ = store.MigrateDown(testDatabaseURL) // best-effort cleanup from a prior run
		if err := store.MigrateUp(testDatabaseURL); err != nil {
			fmt.Fprintln(os.Stderr, "store_test: migrate up failed:", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

// skipIfNoDB is called first by every test in this package that needs a
// real PostgreSQL connection, so `go test ./...` still passes cleanly on a
// machine with no database running (see docs/dev-environment.md).
func skipIfNoDB(t *testing.T) string {
	t.Helper()
	if testDatabaseURL == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	return testDatabaseURL
}

func connString(t *testing.T, baseURL, user, password string) string {
	t.Helper()
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parsing TEST_DATABASE_URL: %v", err)
	}
	u.User = url.UserPassword(user, password)
	return u.String()
}

func connectAs(t *testing.T, ctx context.Context, baseURL, user, password string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, connString(t, baseURL, user, password))
	if err != nil {
		t.Fatalf("connecting as %s: %v", user, err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	return conn
}

// openStoreAs opens a *store.DB (the pool-backed handle the real
// repository methods use) as a specific role, for tests exercising those
// methods directly rather than through raw SQL.
func openStoreAs(t *testing.T, ctx context.Context, baseURL, user, password string) *store.DB {
	t.Helper()
	db, err := store.Open(ctx, connString(t, baseURL, user, password))
	if err != nil {
		t.Fatalf("opening store as %s: %v", user, err)
	}
	t.Cleanup(db.Close)
	return db
}

// insertApplication creates a minimal application row and registers its
// cleanup, returning the new row's id.
func insertApplication(t *testing.T, ctx context.Context, conn *pgx.Conn, hostname string) string {
	t.Helper()
	var id string
	err := conn.QueryRow(ctx, `
		INSERT INTO applications (hostname, display_name, default_duration_seconds, max_duration_seconds)
		VALUES ($1, $2, 60, 120)
		RETURNING id`, hostname, "Test: "+hostname).Scan(&id)
	if err != nil {
		t.Fatalf("inserting application %s: %v", hostname, err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM applications WHERE id = $1`, id) })
	return id
}

// insertApprovalRequest creates a minimal approval_requests row for
// applicationID and registers its cleanup, returning the new row's id.
func insertApprovalRequest(t *testing.T, ctx context.Context, conn *pgx.Conn, applicationID, verificationCode string) string {
	t.Helper()
	tokenHash := sha256.Sum256([]byte(applicationID + ":" + verificationCode))

	var id string
	err := conn.QueryRow(ctx, `
		INSERT INTO approval_requests (application_id, pending_token_hash, verification_code, deadline_at)
		VALUES ($1, $2, $3, now() + interval '1 hour')
		RETURNING id`, applicationID, tokenHash[:], verificationCode).Scan(&id)
	if err != nil {
		t.Fatalf("inserting approval_request: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, id) })
	return id
}

// insertMatchingEnrollmentContext seeds an enrollment_contexts row with
// the exact same pending_token_hash insertApprovalRequest computes for
// the same (applicationID, verificationCode) pair, so a test can assert
// that a request-lifecycle transition also consumed its context.
func insertMatchingEnrollmentContext(t *testing.T, ctx context.Context, conn *pgx.Conn, applicationID, verificationCode string) string {
	t.Helper()
	tokenHash := sha256.Sum256([]byte(applicationID + ":" + verificationCode))

	var id string
	err := conn.QueryRow(ctx, `
		INSERT INTO enrollment_contexts (application_id, pending_token_hash, csrf_secret, expires_at)
		VALUES ($1, $2, $3, now() + interval '1 hour')
		RETURNING id`, applicationID, tokenHash[:], []byte("csrf-secret-bytes")).Scan(&id)
	if err != nil {
		t.Fatalf("inserting enrollment_context: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM enrollment_contexts WHERE id = $1`, id) })
	return id
}

// authorizationOpts controls the state of a seeded authorization row --
// tests set only the fields relevant to the scenario under test.
type authorizationOpts struct {
	ExpiresAt   time.Time
	ActivatedAt *time.Time // nil = not yet activated (unclaimed)
	RevokedAt   *time.Time // nil = not revoked
}

// insertAuthorization seeds an authorization row directly via SQL --
// there is no store.CreateAuthorization yet (that's the real approve/
// claim flow, Milestone 3), so tests construct the state authz.Decide
// needs to see by hand.
func insertAuthorization(t *testing.T, ctx context.Context, conn *pgx.Conn, applicationID, requestID string, opts authorizationOpts) string {
	t.Helper()
	var id string
	err := conn.QueryRow(ctx, `
		INSERT INTO authorizations (application_id, request_id, approved_by, activated_at, expires_at, revoked_at)
		VALUES ($1, $2, 'tester', $3, $4, $5)
		RETURNING id`, applicationID, requestID, opts.ActivatedAt, opts.ExpiresAt, opts.RevokedAt).Scan(&id)
	if err != nil {
		t.Fatalf("inserting authorization: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM authorizations WHERE id = $1`, id) })
	return id
}

type credentialOpts struct {
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time // nil = not revoked
}

// insertCredential seeds a credential row for a known raw tokenHash, so
// the test can present the corresponding raw token as a cookie value.
func insertCredential(t *testing.T, ctx context.Context, conn *pgx.Conn, authorizationID, applicationID string, tokenHash []byte, opts credentialOpts) string {
	t.Helper()
	var id string
	err := conn.QueryRow(ctx, `
		INSERT INTO credentials (authorization_id, application_id, token_hash, absolute_expires_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`, authorizationID, applicationID, tokenHash, opts.AbsoluteExpiresAt, opts.RevokedAt).Scan(&id)
	if err != nil {
		t.Fatalf("inserting credential: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM credentials WHERE id = $1`, id) })
	return id
}
