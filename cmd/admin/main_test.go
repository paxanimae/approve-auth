package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/paxanimae/approve-auth/internal/store"
)

// skipIfNoDB mirrors internal/store's own helper of the same name: every
// test here that needs a real PostgreSQL connection skips cleanly when
// TEST_DATABASE_URL isn't set, so `go test ./...` still passes on a
// machine with no database running.
func skipIfNoDB(t *testing.T) string {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	return dbURL
}

// setDatabaseURLFile points DATABASE_URL_FILE (what config.Load reads)
// at a temp file holding dbURL, the same way a real deployment's secret
// mount does -- config.Load refuses a bare DATABASE_URL env var.
func setDatabaseURLFile(t *testing.T, dbURL string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "database-url.txt")
	if err := os.WriteFile(path, []byte(dbURL), 0o600); err != nil {
		t.Fatalf("writing database url file: %v", err)
	}
	t.Setenv("DATABASE_URL_FILE", path)
	t.Setenv("CONFIG_FILE", "")
}

func openTestDB(t *testing.T, ctx context.Context, dbURL string) *store.DB {
	t.Helper()
	db, err := store.Open(ctx, dbURL)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func cleanupApplication(t *testing.T, ctx context.Context, db *store.DB, hostname string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE hostname = $1`, hostname)
	})
}

func TestRegisterApplication_AllowAnonymousMessageAndRevokePolicy(t *testing.T) {
	dbURL := skipIfNoDB(t)
	setDatabaseURLFile(t, dbURL)
	ctx := context.Background()
	db := openTestDB(t, ctx, dbURL)

	const hostname = "cmd-admin-test-flags.example.test"
	cleanupApplication(t, ctx, db, hostname)

	if err := run([]string{
		"register-application",
		"-hostname=" + hostname,
		"-display-name=CLI Flags Test",
		"-allow-anonymous-message",
		"-revoke-policy-ip-changed=revoke",
		"-revoke-policy-user-agent-changed=warn",
	}); err != nil {
		t.Fatalf("run(register-application): %v", err)
	}

	app, ok, err := db.GetApplicationByHostname(ctx, hostname)
	if err != nil {
		t.Fatalf("GetApplicationByHostname: %v", err)
	}
	if !ok {
		t.Fatal("application was not created")
	}
	if !app.AllowAnonymousMessage {
		t.Error("AllowAnonymousMessage = false, want true")
	}
	if app.RevokePolicyIPChanged == nil || *app.RevokePolicyIPChanged != "revoke" {
		t.Errorf("RevokePolicyIPChanged = %v, want \"revoke\"", app.RevokePolicyIPChanged)
	}
	if app.RevokePolicyUserAgentChanged == nil || *app.RevokePolicyUserAgentChanged != "warn" {
		t.Errorf("RevokePolicyUserAgentChanged = %v, want \"warn\"", app.RevokePolicyUserAgentChanged)
	}
}

func TestRegisterApplication_InvalidRevokePolicyRejectedBeforeAnyDBWrite(t *testing.T) {
	dbURL := skipIfNoDB(t)
	setDatabaseURLFile(t, dbURL)
	ctx := context.Background()
	db := openTestDB(t, ctx, dbURL)

	const hostname = "cmd-admin-test-invalid-policy.example.test"
	cleanupApplication(t, ctx, db, hostname)

	err := run([]string{
		"register-application",
		"-hostname=" + hostname,
		"-display-name=Invalid Policy Test",
		"-revoke-policy-ip-changed=not-a-real-action",
	})
	if err == nil {
		t.Fatal("run(register-application): expected an error for an invalid revocation action, got nil")
	}

	if _, ok, err := db.GetApplicationByHostname(ctx, hostname); err != nil {
		t.Fatalf("GetApplicationByHostname: %v", err)
	} else if ok {
		t.Error("application should not have been created when validation fails")
	}
}

func TestRegisterApplication_IfNotExistsIsIdempotent(t *testing.T) {
	dbURL := skipIfNoDB(t)
	setDatabaseURLFile(t, dbURL)
	ctx := context.Background()
	db := openTestDB(t, ctx, dbURL)

	const hostname = "cmd-admin-test-if-not-exists.example.test"
	cleanupApplication(t, ctx, db, hostname)

	args := []string{
		"register-application",
		"-hostname=" + hostname,
		"-display-name=If Not Exists Test",
		"-if-not-exists",
	}
	if err := run(args); err != nil {
		t.Fatalf("run(register-application) first call: %v", err)
	}
	first, _, err := db.GetApplicationByHostname(ctx, hostname)
	if err != nil {
		t.Fatalf("GetApplicationByHostname: %v", err)
	}

	// Re-running with -if-not-exists must succeed without creating a
	// second row or changing the existing one -- this is what makes the
	// demo stack's seed step safe to run every `docker compose up -d`.
	if err := run(args); err != nil {
		t.Fatalf("run(register-application) second call with -if-not-exists: %v", err)
	}
	second, _, err := db.GetApplicationByHostname(ctx, hostname)
	if err != nil {
		t.Fatalf("GetApplicationByHostname: %v", err)
	}
	if first.ID != second.ID || first.Version != second.Version {
		t.Errorf("second -if-not-exists call changed the application: first=%+v second=%+v", first, second)
	}
}

func TestRegisterApplication_WithoutIfNotExistsErrorsOnDuplicate(t *testing.T) {
	dbURL := skipIfNoDB(t)
	setDatabaseURLFile(t, dbURL)
	ctx := context.Background()
	db := openTestDB(t, ctx, dbURL)

	const hostname = "cmd-admin-test-duplicate.example.test"
	cleanupApplication(t, ctx, db, hostname)

	args := []string{
		"register-application",
		"-hostname=" + hostname,
		"-display-name=Duplicate Test",
	}
	if err := run(args); err != nil {
		t.Fatalf("run(register-application) first call: %v", err)
	}
	if err := run(args); err == nil {
		t.Fatal("run(register-application) second call without -if-not-exists: expected a duplicate-hostname error, got nil")
	}
}
