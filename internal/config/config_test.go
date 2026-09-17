package config_test

import (
	"strings"
	"testing"

	"github.com/frid-iks/traefik-manual-proxy/internal/config"
)

func setSecretEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL_FILE", "testdata/secrets/database-url.txt")
	t.Setenv("OIDC_CLIENT_SECRET_FILE", "testdata/secrets/oidc-client-secret.txt")
	t.Setenv("CLAIM_ENCRYPTION_KEY_FILE", "testdata/secrets/claim-encryption-key.txt")
	t.Setenv("OIDC_STATE_ENCRYPTION_KEY_FILE", "testdata/secrets/oidc-state-key.txt")
}

func TestLoadAndValidate_HappyPath(t *testing.T) {
	setSecretEnv(t)

	cfg, err := config.Load("testdata/valid.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if cfg.DatabaseURL == "" {
		t.Error("DatabaseURL was not populated from DATABASE_URL_FILE")
	}
	if len(cfg.ClaimEncryptionKey) != 32 {
		t.Errorf("ClaimEncryptionKey: got %d bytes, want 32", len(cfg.ClaimEncryptionKey))
	}
	if cfg.PublicAddr == "" || cfg.AdminAddr == "" || cfg.AuthAddr == "" || cfg.OpsAddr == "" {
		t.Error("listener addr defaults were not applied")
	}
}

func TestValidate_MissingAdminOrigin(t *testing.T) {
	setSecretEnv(t)

	cfg, err := config.Load("testdata/missing_admin_origin.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "ADMIN_ORIGIN") {
		t.Errorf("Validate error %q does not mention ADMIN_ORIGIN", err)
	}
}

func TestValidate_BadDurationOrdering(t *testing.T) {
	setSecretEnv(t)

	cfg, err := config.Load("testdata/bad_duration_ordering.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "DEFAULT_AUTHORIZATION_DURATION must not exceed MAX_AUTHORIZATION_DURATION") {
		t.Errorf("Validate error %q does not mention the duration-ordering violation", err)
	}
}

func TestLoad_InlineSecretRejected(t *testing.T) {
	setSecretEnv(t)
	t.Setenv("OIDC_CLIENT_SECRET", "should-not-be-allowed-inline")

	_, err := config.Load("testdata/valid.yaml")
	if err == nil {
		t.Fatal("Load: expected error when OIDC_CLIENT_SECRET is set inline, got nil")
	}
	if !strings.Contains(err.Error(), "OIDC_CLIENT_SECRET_FILE") {
		t.Errorf("Load error %q does not point at the _FILE alternative", err)
	}
}

func TestLoad_InlineSecretRejectedEvenWhenEmpty(t *testing.T) {
	setSecretEnv(t)
	t.Setenv("DATABASE_URL", "")

	_, err := config.Load("testdata/valid.yaml")
	if err == nil {
		t.Fatal("Load: expected error when DATABASE_URL is set (even to empty string), got nil")
	}
}

func TestValidate_RejectsBadClaimEncryptionKeyLength(t *testing.T) {
	setSecretEnv(t)
	t.Setenv("CLAIM_ENCRYPTION_KEY_FILE", "testdata/secrets/oidc-client-secret.txt") // wrong length, not a key

	_, err := config.Load("testdata/valid.yaml")
	if err == nil {
		t.Fatal("Load: expected a decode error for a non-base64/wrong-length key, got nil")
	}
}

func TestValidate_RejectsDuplicateListenerAddrs(t *testing.T) {
	setSecretEnv(t)
	t.Setenv("ADMIN_ADDR", ":8080") // collides with the default PUBLIC_ADDR

	cfg, err := config.Load("testdata/valid.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate: expected error for duplicate listener addresses, got nil")
	}
	if !strings.Contains(err.Error(), "must not share the same address") {
		t.Errorf("Validate error %q does not mention the address collision", err)
	}
}
