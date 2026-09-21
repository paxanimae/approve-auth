package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
)

var validLogLevels = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}

// Validate aggregates every configuration failure it finds via errors.Join,
// rather than stopping at the first one, so an operator fixing a broken
// config sees the whole list in one run. Callers (cmd/server, cmd/admin)
// must treat any non-nil error as fatal before binding a listener.
func (c *Config) Validate() error {
	var errs []error

	errs = append(errs, requireHTTPSOrigin("ADMIN_ORIGIN", c.AdminOrigin))

	switch c.AdminAuthMode {
	case "oidc":
		errs = append(errs, requireURL("OIDC_ISSUER", c.OIDCIssuer))
		errs = append(errs, requireNonEmpty("OIDC_CLIENT_ID", c.OIDCClientID))
		errs = append(errs, requireNonEmpty("OIDC_CLIENT_SECRET_FILE", c.OIDCClientSecret))
		if len(c.OIDCStateEncryptionKey) != 32 {
			errs = append(errs, fmt.Errorf("OIDC_STATE_ENCRYPTION_KEY_FILE: required 32-byte key, got %d bytes", len(c.OIDCStateEncryptionKey)))
		}
	case "anonymous":
		// This service's own login is skipped entirely (see
		// internal/adminsession.Anonymous) -- none of the OIDC settings
		// above apply, but the fixed identity every caller resolves to
		// must still be well-formed, since it's what ends up in the
		// audit trail and gates mutation access.
		errs = append(errs, requireNonEmpty("ADMIN_ANONYMOUS_SUBJECT", c.AdminAnonymousSubject))
		if c.AdminAnonymousRole != "administrator" && c.AdminAnonymousRole != "viewer" {
			errs = append(errs, fmt.Errorf("ADMIN_ANONYMOUS_ROLE: must be administrator or viewer, got %q", c.AdminAnonymousRole))
		}
	default:
		errs = append(errs, fmt.Errorf("ADMIN_AUTH_MODE: must be oidc or anonymous, got %q", c.AdminAuthMode))
	}

	errs = append(errs, requireNonEmpty("DATABASE_URL_FILE", c.DatabaseURL))
	if len(c.ClaimEncryptionKey) != 32 {
		errs = append(errs, fmt.Errorf("CLAIM_ENCRYPTION_KEY_FILE: required 32-byte key, got %d bytes", len(c.ClaimEncryptionKey)))
	}
	errs = append(errs, requireNonEmpty("CLAIM_ENCRYPTION_KEY_ID", c.ClaimEncryptionKeyID))

	errs = append(errs, requireReadableFile("AUTH_TLS_CERT_FILE", c.AuthTLSCertFile))
	errs = append(errs, requireReadableFile("AUTH_TLS_KEY_FILE", c.AuthTLSKeyFile))
	errs = append(errs, requireReadableFile("AUTH_CLIENT_CA_FILE", c.AuthClientCAFile))
	if len(c.AuthAllowedClientIdentities) == 0 {
		errs = append(errs, errors.New("AUTH_ALLOWED_CLIENT_IDENTITIES: required (the /auth listener always requires mTLS)"))
	}

	if len(c.TrustedTraefikCIDRs) == 0 {
		errs = append(errs, errors.New("TRUSTED_TRAEFIK_CIDRS: required (no default; forwarded metadata must never be trusted implicitly)"))
	}
	for _, raw := range c.TrustedTraefikCIDRs {
		if _, _, err := net.ParseCIDR(raw); err != nil {
			errs = append(errs, fmt.Errorf("TRUSTED_TRAEFIK_CIDRS: invalid CIDR %q: %w", raw, err))
		}
	}

	errs = append(errs, positiveDuration("DEFAULT_AUTHORIZATION_DURATION", c.DefaultAuthorizationDuration))
	errs = append(errs, positiveDuration("MAX_AUTHORIZATION_DURATION", c.MaxAuthorizationDuration))
	errs = append(errs, positiveDuration("CREDENTIAL_MAX_AGE", c.CredentialMaxAge))
	errs = append(errs, positiveDuration("REQUEST_TTL", c.RequestTTL))
	errs = append(errs, positiveDuration("CLAIM_TTL", c.ClaimTTL))
	errs = append(errs, positiveDuration("CLAIM_RETRY_TTL", c.ClaimRetryTTL))
	errs = append(errs, positiveDuration("EXPIRING_SOON_WINDOW", c.ExpiringSoonWindow))
	errs = append(errs, positiveDuration("ADMIN_IDLE_TTL", c.AdminIdleTTL))
	errs = append(errs, positiveDuration("ADMIN_ABSOLUTE_TTL", c.AdminAbsoluteTTL))
	errs = append(errs, positiveDuration("AUTH_DECISION_TIMEOUT", c.AuthDecisionTimeout))

	if c.DefaultAuthorizationDuration.Std() > c.MaxAuthorizationDuration.Std() {
		errs = append(errs, errors.New("DEFAULT_AUTHORIZATION_DURATION must not exceed MAX_AUTHORIZATION_DURATION"))
	}
	if c.MaxAuthorizationDuration.Std() > c.CredentialMaxAge.Std() {
		errs = append(errs, errors.New("MAX_AUTHORIZATION_DURATION must not exceed CREDENTIAL_MAX_AGE (authorizations cannot outlive their credential)"))
	}
	if c.ClaimTTL.Std() > c.RequestTTL.Std() {
		errs = append(errs, errors.New("CLAIM_TTL must not exceed REQUEST_TTL"))
	}
	if c.AdminIdleTTL.Std() > c.AdminAbsoluteTTL.Std() {
		errs = append(errs, errors.New("ADMIN_IDLE_TTL must not exceed ADMIN_ABSOLUTE_TTL"))
	}

	if !validLogLevels[c.LogLevel] {
		errs = append(errs, fmt.Errorf("LOG_LEVEL: must be one of debug/info/warn/error, got %q", c.LogLevel))
	}

	if c.NotifySMTPHost != "" {
		if c.NotifySMTPPort <= 0 || c.NotifySMTPPort > 65535 {
			errs = append(errs, fmt.Errorf("NOTIFY_SMTP_PORT: must be between 1 and 65535, got %d", c.NotifySMTPPort))
		}
	}

	// Every rate limit here is a fail-closed abuse control (spec section
	// 11) whose own check code treats a non-positive value as "disabled"
	// (endpoint-review.md F2: "checks are conditional on positive
	// configured values; non-positive values disable them ...
	// explicit configuration validation should prevent accidental
	// disabling"). There is no supported deployment scenario where any
	// of these should be off -- a misconfigured 0 must fail startup
	// loudly, not silently remove a limit.
	errs = append(errs, positiveInt("rate_limits.pending_requests_per_hour_per_app_ip", c.RateLimits.PendingRequestsPerHourPerAppIP))
	errs = append(errs, positiveInt("rate_limits.bootstrap_per_minute_per_ip", c.RateLimits.BootstrapPerMinutePerIP))
	errs = append(errs, positiveInt("rate_limits.status_per_minute_per_pending_proof", c.RateLimits.StatusPerMinutePerPendingProof))
	errs = append(errs, positiveInt("rate_limits.admin_writes_per_minute_per_admin", c.RateLimits.AdminWritesPerMinutePerAdmin))
	errs = append(errs, positiveInt("rate_limits.global_enrollment_per_hour", c.RateLimits.GlobalEnrollmentPerHour))

	errs = append(errs, distinctListenerAddrs(c))

	return errors.Join(errs...)
}

func requireNonEmpty(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s: required", field)
	}
	return nil
}

func requireURL(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s: required", field)
	}
	if _, err := url.ParseRequestURI(value); err != nil {
		return fmt.Errorf("%s: invalid URL %q: %w", field, value, err)
	}
	return nil
}

func requireHTTPSOrigin(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s: required", field)
	}
	u, err := url.ParseRequestURI(value)
	if err != nil {
		return fmt.Errorf("%s: invalid URL %q: %w", field, value, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s: must be an https:// origin, got %q", field, value)
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("%s: must be an origin with no path, got %q", field, value)
	}
	return nil
}

func requireReadableFile(field, path string) error {
	if path == "" {
		return fmt.Errorf("%s: required", field)
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func positiveDuration(field string, d Duration) error {
	if d.Std() <= 0 {
		return fmt.Errorf("%s: must be positive, got %s", field, d.Std())
	}
	return nil
}

func positiveInt(field string, v int) error {
	if v <= 0 {
		return fmt.Errorf("%s: must be positive, got %d", field, v)
	}
	return nil
}

func distinctListenerAddrs(c *Config) error {
	addrs := map[string]string{
		"PUBLIC_ADDR": c.PublicAddr,
		"ADMIN_ADDR":  c.AdminAddr,
		"AUTH_ADDR":   c.AuthAddr,
		"OPS_ADDR":    c.OpsAddr,
	}
	seen := make(map[string]string, len(addrs))
	var errs []error
	for field, addr := range addrs {
		if addr == "" {
			errs = append(errs, fmt.Errorf("%s: required", field))
			continue
		}
		if other, ok := seen[addr]; ok {
			errs = append(errs, fmt.Errorf("%s and %s must not share the same address %q (listeners must be independently bound)", other, field, addr))
			continue
		}
		seen[addr] = field
	}
	return errors.Join(errs...)
}
