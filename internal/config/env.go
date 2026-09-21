package config

import (
	"fmt"
	"os"
	"strings"
)

// envOverride binds one environment variable to a setter applied against a
// Config being loaded. Kept as a table (rather than a struct of ad hoc
// `if v, ok := os.LookupEnv(...)` blocks) so every override is visible in
// one place and env_test.go can iterate it.
type envOverride struct {
	name string
	set  func(cfg *Config, value string) error
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func durationSetter(name string, dst *Duration) func(*Config, string) error {
	return func(_ *Config, value string) error {
		parsed, err := ParseDurationEnv(name, value)
		if err != nil {
			return err
		}
		*dst = parsed
		return nil
	}
}

func envOverrides(cfg *Config) []envOverride {
	return []envOverride{
		{"ADMIN_ORIGIN", func(c *Config, v string) error { c.AdminOrigin = v; return nil }},
		{"INSTANCE_NAME", func(c *Config, v string) error { c.InstanceName = v; return nil }},
		{"CONTACT_INFO", func(c *Config, v string) error { c.ContactInfo = v; return nil }},
		{"ADMIN_AUTH_MODE", func(c *Config, v string) error { c.AdminAuthMode = v; return nil }},
		{"ADMIN_ANONYMOUS_SUBJECT", func(c *Config, v string) error { c.AdminAnonymousSubject = v; return nil }},
		{"ADMIN_ANONYMOUS_DISPLAY_NAME", func(c *Config, v string) error { c.AdminAnonymousDisplayName = v; return nil }},
		{"ADMIN_ANONYMOUS_ROLE", func(c *Config, v string) error { c.AdminAnonymousRole = v; return nil }},
		{"OIDC_ISSUER", func(c *Config, v string) error { c.OIDCIssuer = v; return nil }},
		{"OIDC_CLIENT_ID", func(c *Config, v string) error { c.OIDCClientID = v; return nil }},
		{"OIDC_ADMIN_GROUPS", func(c *Config, v string) error { c.OIDCAdminGroups = splitCSV(v); return nil }},
		{"OIDC_VIEWER_GROUPS", func(c *Config, v string) error { c.OIDCViewerGroups = splitCSV(v); return nil }},

		{"DATABASE_URL_FILE", func(c *Config, v string) error { c.DatabaseURLFile = v; return nil }},
		{"OIDC_CLIENT_SECRET_FILE", func(c *Config, v string) error { c.OIDCClientSecretFile = v; return nil }},
		{"CLAIM_ENCRYPTION_KEY_FILE", func(c *Config, v string) error { c.ClaimEncryptionKeyFile = v; return nil }},
		{"OIDC_STATE_ENCRYPTION_KEY_FILE", func(c *Config, v string) error { c.OIDCStateEncryptionKeyFile = v; return nil }},
		{"CLAIM_ENCRYPTION_KEY_ID", func(c *Config, v string) error { c.ClaimEncryptionKeyID = v; return nil }},

		{"AUTH_TLS_CERT_FILE", func(c *Config, v string) error { c.AuthTLSCertFile = v; return nil }},
		{"AUTH_TLS_KEY_FILE", func(c *Config, v string) error { c.AuthTLSKeyFile = v; return nil }},
		{"AUTH_CLIENT_CA_FILE", func(c *Config, v string) error { c.AuthClientCAFile = v; return nil }},
		{"AUTH_ALLOWED_CLIENT_IDENTITIES", func(c *Config, v string) error { c.AuthAllowedClientIdentities = splitCSV(v); return nil }},
		{"TRUSTED_TRAEFIK_CIDRS", func(c *Config, v string) error { c.TrustedTraefikCIDRs = splitCSV(v); return nil }},

		{"DEFAULT_AUTHORIZATION_DURATION", durationSetter("DEFAULT_AUTHORIZATION_DURATION", &cfg.DefaultAuthorizationDuration)},
		{"MAX_AUTHORIZATION_DURATION", durationSetter("MAX_AUTHORIZATION_DURATION", &cfg.MaxAuthorizationDuration)},
		{"CREDENTIAL_MAX_AGE", durationSetter("CREDENTIAL_MAX_AGE", &cfg.CredentialMaxAge)},
		{"REQUEST_TTL", durationSetter("REQUEST_TTL", &cfg.RequestTTL)},
		{"CLAIM_TTL", durationSetter("CLAIM_TTL", &cfg.ClaimTTL)},
		{"CLAIM_RETRY_TTL", durationSetter("CLAIM_RETRY_TTL", &cfg.ClaimRetryTTL)},
		{"EXPIRING_SOON_WINDOW", durationSetter("EXPIRING_SOON_WINDOW", &cfg.ExpiringSoonWindow)},
		{"ADMIN_IDLE_TTL", durationSetter("ADMIN_IDLE_TTL", &cfg.AdminIdleTTL)},
		{"ADMIN_ABSOLUTE_TTL", durationSetter("ADMIN_ABSOLUTE_TTL", &cfg.AdminAbsoluteTTL)},
		{"AUTH_DECISION_TIMEOUT", durationSetter("AUTH_DECISION_TIMEOUT", &cfg.AuthDecisionTimeout)},

		{"LOG_LEVEL", func(c *Config, v string) error { c.LogLevel = v; return nil }},

		{"PUBLIC_ADDR", func(c *Config, v string) error { c.PublicAddr = v; return nil }},
		{"ADMIN_ADDR", func(c *Config, v string) error { c.AdminAddr = v; return nil }},
		{"AUTH_ADDR", func(c *Config, v string) error { c.AuthAddr = v; return nil }},
		{"OPS_ADDR", func(c *Config, v string) error { c.OpsAddr = v; return nil }},
	}
}

func applyEnvOverrides(cfg *Config) error {
	for _, o := range envOverrides(cfg) {
		if v, ok := os.LookupEnv(o.name); ok {
			if err := o.set(cfg, v); err != nil {
				return fmt.Errorf("config: env %s: %w", o.name, err)
			}
		}
	}
	return nil
}
