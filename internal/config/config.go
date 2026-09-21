package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// RateLimits mirrors the atomic distributed limits from spec section 11.
type RateLimits struct {
	PendingRequestsPerHourPerAppIP int `yaml:"pending_requests_per_hour_per_app_ip"`
	BootstrapPerMinutePerIP        int `yaml:"bootstrap_per_minute_per_ip"`
	StatusPerMinutePerPendingProof int `yaml:"status_per_minute_per_pending_proof"`
	AdminWritesPerMinutePerAdmin   int `yaml:"admin_writes_per_minute_per_admin"`
	GlobalEnrollmentPerHour        int `yaml:"global_enrollment_per_hour"`
}

// Retention mirrors the default retention windows from spec section 12.
type Retention struct {
	AuditEvents        Duration `yaml:"audit_events"`
	ResolvedRequests   Duration `yaml:"resolved_requests"`
	IPAndUserAgent     Duration `yaml:"ip_and_user_agent"`
	ReturnPaths        Duration `yaml:"return_paths"`
	IdempotencyRecords Duration `yaml:"idempotency_records"`
	ClaimEnvelopes     Duration `yaml:"claim_envelopes"`
}

// Config is the fully loaded, environment-overridden, secret-resolved
// service configuration. See docs/dev-environment.md and spec section 14
// for the settings table this mirrors.
type Config struct {
	AdminOrigin string `yaml:"admin_origin"`

	// InstanceName is a free-text label an operator sets to tell one
	// deployment apart from another in the admin console (e.g. which
	// cluster/environment this is) -- purely informational, never used
	// in any decision. Empty by default; unset is valid.
	InstanceName string `yaml:"instance_name"`

	// ContactInfo is the global default shown on every application's
	// request page (who to contact about access), unless that specific
	// application has its own override (see migration 000014). Empty by
	// default -- unset means no contact info is shown at all.
	ContactInfo string `yaml:"contact_info"`

	// GeoIPDatabasePath is a MaxMind GeoLite2-City (or commercial
	// GeoIP2-City) .mmdb file, used for best-effort country/city
	// enrichment of a new request's source_ip (internal/geoip). Empty
	// (the default) disables the feature entirely -- this repo does not
	// and cannot bundle a database file; MaxMind requires each user to
	// register their own free account. See docs/dev-environment.md.
	GeoIPDatabasePath string `yaml:"geoip_database_path"`

	// AdminAuthMode is "oidc" (default) or "anonymous". Anonymous mode
	// skips this service's own login entirely -- every request to the
	// admin listener is treated as the fixed identity described by the
	// AdminAnonymous* fields below, for a deployment that already gates
	// who can reach the admin listener some other way (a VPN, an
	// upstream SSO reverse proxy, network ACLs). See
	// internal/adminsession.Anonymous for what this does and does not
	// weaken.
	AdminAuthMode             string `yaml:"admin_auth_mode"`
	AdminAnonymousSubject     string `yaml:"admin_anonymous_subject"`
	AdminAnonymousDisplayName string `yaml:"admin_anonymous_display_name"`
	AdminAnonymousRole        string `yaml:"admin_anonymous_role"`

	OIDCIssuer       string   `yaml:"oidc_issuer"`
	OIDCClientID     string   `yaml:"oidc_client_id"`
	OIDCAdminGroups  []string `yaml:"oidc_admin_groups"`
	OIDCViewerGroups []string `yaml:"oidc_viewer_groups"`

	// Secrets: never populated from plain env vars or YAML, only from the
	// file paths named by DatabaseURLFile etc. See secrets.go.
	DatabaseURLFile            string `yaml:"-"`
	OIDCClientSecretFile       string `yaml:"-"`
	ClaimEncryptionKeyFile     string `yaml:"-"`
	OIDCStateEncryptionKeyFile string `yaml:"-"`

	DatabaseURL            string `yaml:"-"`
	OIDCClientSecret       string `yaml:"-"`
	ClaimEncryptionKey     []byte `yaml:"-"`
	OIDCStateEncryptionKey []byte `yaml:"-"`

	ClaimEncryptionKeyID string `yaml:"claim_encryption_key_id"`

	AuthTLSCertFile             string   `yaml:"auth_tls_cert_file"`
	AuthTLSKeyFile              string   `yaml:"auth_tls_key_file"`
	AuthClientCAFile            string   `yaml:"auth_client_ca_file"`
	AuthAllowedClientIdentities []string `yaml:"auth_allowed_client_identities"`

	TrustedTraefikCIDRs []string `yaml:"trusted_traefik_cidrs"`

	DefaultAuthorizationDuration Duration `yaml:"default_authorization_duration"`
	MaxAuthorizationDuration     Duration `yaml:"max_authorization_duration"`
	CredentialMaxAge             Duration `yaml:"credential_max_age"`
	RequestTTL                   Duration `yaml:"request_ttl"`
	ClaimTTL                     Duration `yaml:"claim_ttl"`
	ClaimRetryTTL                Duration `yaml:"claim_retry_ttl"`
	ExpiringSoonWindow           Duration `yaml:"expiring_soon_window"`
	AdminIdleTTL                 Duration `yaml:"admin_idle_ttl"`
	AdminAbsoluteTTL             Duration `yaml:"admin_absolute_ttl"`
	AuthDecisionTimeout          Duration `yaml:"auth_decision_timeout"`

	LogLevel string `yaml:"log_level"`

	RateLimits RateLimits `yaml:"rate_limits"`
	Retention  Retention  `yaml:"retention"`

	PublicAddr string `yaml:"public_addr"`
	AdminAddr  string `yaml:"admin_addr"`
	AuthAddr   string `yaml:"auth_addr"`
	OpsAddr    string `yaml:"ops_addr"`
}

// Defaults returns the spec-mandated defaults (section 11/14) before any
// YAML file or environment override is applied.
func Defaults() *Config {
	hours := func(h float64) Duration {
		d, err := ParseDurationEnv("default", fmt.Sprintf("%gh", h))
		if err != nil {
			panic(err) // constant input; cannot fail
		}
		return d
	}
	return &Config{
		AdminAuthMode:             "oidc",
		AdminAnonymousSubject:     "anonymous",
		AdminAnonymousDisplayName: "Anonymous",
		AdminAnonymousRole:        "administrator",

		ClaimEncryptionKeyID: "primary",

		DefaultAuthorizationDuration: hours(30 * 24),
		MaxAuthorizationDuration:     hours(365 * 24),
		CredentialMaxAge:             hours(365 * 24),
		RequestTTL:                   hours(24),
		ClaimTTL:                     hours(0.5),
		ClaimRetryTTL:                hours(1.0 / 6),
		ExpiringSoonWindow:           hours(7 * 24),
		AdminIdleTTL:                 hours(0.5),
		AdminAbsoluteTTL:             hours(8),
		AuthDecisionTimeout:          Duration(2_000_000_000), // 2s, in ns

		LogLevel: "info",

		RateLimits: RateLimits{
			PendingRequestsPerHourPerAppIP: 5,
			BootstrapPerMinutePerIP:        30,
			StatusPerMinutePerPendingProof: 20,
			AdminWritesPerMinutePerAdmin:   60,
			GlobalEnrollmentPerHour:        1000,
		},
		Retention: Retention{
			AuditEvents:        hours(365 * 24),
			ResolvedRequests:   hours(90 * 24),
			IPAndUserAgent:     hours(30 * 24),
			ReturnPaths:        hours(7 * 24),
			IdempotencyRecords: hours(24),
			ClaimEnvelopes:     hours(1.0 / 6),
		},

		PublicAddr: ":8080",
		AdminAddr:  ":8081",
		AuthAddr:   ":8443",
		OpsAddr:    ":9090",
	}
}

// Load builds a Config from defaults, an optional YAML file, environment
// overrides, and secret files, in that order. It does not call Validate --
// callers (cmd/server, cmd/admin) must call Validate explicitly and refuse
// to start on error, per the spec's "invalid security configuration
// prevents readiness" requirement.
func Load(yamlPath string) (*Config, error) {
	cfg := Defaults()

	if yamlPath != "" {
		data, err := os.ReadFile(yamlPath)
		if err != nil {
			return nil, fmt.Errorf("config: reading %s: %w", yamlPath, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: parsing %s: %w", yamlPath, err)
		}
	}

	if err := applyEnvOverrides(cfg); err != nil {
		return nil, err
	}

	if err := loadSecrets(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
