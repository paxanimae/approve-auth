package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// secretBase names a secret whose value must come only from <base>_FILE.
// If the bare env var is set at all -- present, regardless of value -- Load
// fails hard rather than silently ignoring it, so an operator can never
// accidentally pass a secret inline via a plain environment variable.
type secretBase struct {
	envBase string
	file    func(cfg *Config) string
	assign  func(cfg *Config, raw string) error
}

func secretBases(cfg *Config) []secretBase {
	return []secretBase{
		{
			envBase: "DATABASE_URL",
			file:    func(c *Config) string { return c.DatabaseURLFile },
			assign:  func(c *Config, raw string) error { c.DatabaseURL = raw; return nil },
		},
		{
			envBase: "OIDC_CLIENT_SECRET",
			file:    func(c *Config) string { return c.OIDCClientSecretFile },
			assign:  func(c *Config, raw string) error { c.OIDCClientSecret = raw; return nil },
		},
		{
			envBase: "CLAIM_ENCRYPTION_KEY",
			file:    func(c *Config) string { return c.ClaimEncryptionKeyFile },
			assign:  func(c *Config, raw string) error {
				key, err := decodeAESKey("CLAIM_ENCRYPTION_KEY_FILE", raw)
				if err != nil {
					return err
				}
				c.ClaimEncryptionKey = key
				return nil
			},
		},
		{
			envBase: "OIDC_STATE_ENCRYPTION_KEY",
			file:    func(c *Config) string { return c.OIDCStateEncryptionKeyFile },
			assign:  func(c *Config, raw string) error {
				key, err := decodeAESKey("OIDC_STATE_ENCRYPTION_KEY_FILE", raw)
				if err != nil {
					return err
				}
				c.OIDCStateEncryptionKey = key
				return nil
			},
		},
	}
}

func decodeAESKey(source, raw string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("config: %s: expected base64-encoded 32-byte key: %w", source, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("config: %s: expected 32-byte key, got %d bytes", source, len(key))
	}
	return key, nil
}

// loadSecrets enforces the "_FILE only" invariant and, for any base whose
// *_FILE path is set, reads and assigns it. A base whose file path is empty
// is left unresolved -- Validate is responsible for deciding whether that's
// acceptable (e.g. it never is, today, but a future optional secret could
// use this same mechanism).
func loadSecrets(cfg *Config) error {
	for _, b := range secretBases(cfg) {
		if _, ok := os.LookupEnv(b.envBase); ok {
			return fmt.Errorf("config: %s must not be set directly; use %s_FILE", b.envBase, b.envBase)
		}
		path := b.file(cfg)
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("config: reading %s_FILE (%s): %w", b.envBase, path, err)
		}
		if err := b.assign(cfg, strings.TrimRight(string(data), "\r\n")); err != nil {
			return err
		}
	}
	return nil
}
