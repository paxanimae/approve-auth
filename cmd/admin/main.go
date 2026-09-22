// Command admin is the operator CLI: it talks to PostgreSQL directly for
// tasks like registering the first application or force-revoking an admin
// session (spec section 9), rather than being a network listener like
// cmd/server. See docs/adr/0002-cmd-admin-is-a-cli-not-a-listener.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/paxanimae/approve-auth/internal/config"
	"github.com/paxanimae/approve-auth/internal/revokepolicy"
	"github.com/paxanimae/approve-auth/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}

	switch args[0] {
	case "register-application":
		return runRegisterApplication(args[1:])
	case "migrate-up":
		return runMigrate(args[1:], "migrate-up", store.MigrateUp)
	case "migrate-down":
		return runMigrate(args[1:], "migrate-down", store.MigrateDown)
	case "revoke-admin-session":
		return runRevokeAdminSession(args[1:])
	case "purge-audit-log":
		return runPurgeAuditLog(args[1:])
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `approve-auth admin CLI (operator tool, connects to PostgreSQL directly)

Usage:
  admin <command> [flags]

Commands:
  register-application    Register a new protected application
  migrate-up              Apply pending migrations (needs a privileged connection -- see spec section 13)
  migrate-down            Reverse applied migrations (tests/local dev only)
  revoke-admin-session    Force-revoke all of one admin's sessions by OIDC issuer/subject
  purge-audit-log         Delete audit_events older than -max-age (needs an app_maintenance
                          connection -- see spec section 11, control 10)
`)
}

// runMigrate backs both migrate-up and migrate-down: schema migrations
// are a separate, privileged, one-off step (spec section 13), not
// something cmd/server does with its own least-privilege runtime role
// (migration 000012's CREATE ROLE statements need more than that).
func runMigrate(args []string, name string, apply func(databaseURL string) error) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	configFile := fs.String("config", os.Getenv("CONFIG_FILE"), "path to the nonsecret YAML config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL_FILE is not set (see -config or the env var)")
	}

	if err := apply(cfg.DatabaseURL); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	fmt.Printf("%s: done\n", name)
	return nil
}

func runRegisterApplication(args []string) error {
	fs := flag.NewFlagSet("register-application", flag.ContinueOnError)
	configFile := fs.String("config", os.Getenv("CONFIG_FILE"), "path to the nonsecret YAML config file")
	hostname := fs.String("hostname", "", "exact application hostname (required)")
	displayName := fs.String("display-name", "", "human-readable name (required)")
	description := fs.String("description", "", "optional description")
	defaultDuration := fs.Duration("default-duration", 30*24*time.Hour, "default authorization duration (e.g. 720h)")
	maxDuration := fs.Duration("max-duration", 365*24*time.Hour, "maximum authorization duration (e.g. 8760h)")
	contactInfo := fs.String("contact-info", "", "optional contact info shown on this application's request page, overriding the global default")
	notifyEmail := fs.String("notify-email", "", "optional notification email address for this application, overriding the global default")
	notifyWebhookURL := fs.String("notify-webhook-url", "", "optional outbound webhook URL for this application, overriding the global default")
	allowAnonymousMessage := fs.Bool("allow-anonymous-message", false, "allow an unverified label/message on this application's request page")
	revokePolicyIPChanged := fs.String("revoke-policy-ip-changed", "", "override the deployment-wide ip_changed revocation action (off|warn|flag_for_review|revoke), empty leaves it inherited")
	revokePolicyUserAgentChanged := fs.String("revoke-policy-user-agent-changed", "", "override the deployment-wide user_agent_changed revocation action, empty leaves it inherited")
	revokePolicyInactivityExceeded := fs.String("revoke-policy-inactivity-exceeded", "", "override the deployment-wide inactivity_exceeded revocation action, empty leaves it inherited")
	ifNotExists := fs.Bool("if-not-exists", false, "exit successfully without changes if hostname is already registered, instead of erroring")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *hostname == "" {
		return fmt.Errorf("register-application: -hostname is required")
	}
	if *displayName == "" {
		return fmt.Errorf("register-application: -display-name is required")
	}
	for flagName, v := range map[string]string{
		"-revoke-policy-ip-changed":          *revokePolicyIPChanged,
		"-revoke-policy-user-agent-changed":  *revokePolicyUserAgentChanged,
		"-revoke-policy-inactivity-exceeded": *revokePolicyInactivityExceeded,
	} {
		if v != "" && !revokepolicy.Action(v).Valid() {
			return fmt.Errorf("register-application: %s: invalid revocation action %q", flagName, v)
		}
	}

	cfg, err := config.Load(*configFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL_FILE is not set (see -config or the env var)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	if *ifNotExists {
		if existing, found, err := db.GetApplicationByHostname(ctx, *hostname); err != nil {
			return fmt.Errorf("checking for existing application: %w", err)
		} else if found {
			fmt.Printf("application already registered, skipping (id=%s, hostname=%s)\n", existing.ID, existing.Hostname)
			return nil
		}
	}

	app, err := db.CreateApplication(ctx, *hostname, *displayName, *description, *defaultDuration, *maxDuration, *contactInfo, *notifyEmail, *notifyWebhookURL)
	if err != nil {
		return fmt.Errorf("registering application: %w", err)
	}

	// CreateApplication has no params for these -- they're applied as a
	// follow-up update, the same way an admin would set them after
	// creation via the admin console's Applications view.
	if *allowAnonymousMessage || *revokePolicyIPChanged != "" || *revokePolicyUserAgentChanged != "" || *revokePolicyInactivityExceeded != "" {
		updateParams := store.UpdateApplicationParams{}
		if *allowAnonymousMessage {
			updateParams.AllowAnonymousMessage = allowAnonymousMessage
		}
		if *revokePolicyIPChanged != "" {
			updateParams.RevokePolicyIPChanged = revokePolicyIPChanged
		}
		if *revokePolicyUserAgentChanged != "" {
			updateParams.RevokePolicyUserAgentChanged = revokePolicyUserAgentChanged
		}
		if *revokePolicyInactivityExceeded != "" {
			updateParams.RevokePolicyInactivityExceeded = revokePolicyInactivityExceeded
		}
		app, err = db.UpdateApplication(ctx, app.ID, app.Version, updateParams, "cmd-admin")
		if err != nil {
			return fmt.Errorf("applying anonymous-message/revocation-policy settings: %w", err)
		}
	}

	fmt.Printf("registered application %s (hostname=%s, enabled=%v)\n", app.ID, app.Hostname, app.Enabled)
	return nil
}

// runRevokeAdminSession backs spec section 9's "deployment CLI command to
// revoke sessions by issuer/subject for urgent removal" -- an operator
// action that must work even if the admin console itself, or the
// identity provider, is unreachable.
func runRevokeAdminSession(args []string) error {
	fs := flag.NewFlagSet("revoke-admin-session", flag.ContinueOnError)
	configFile := fs.String("config", os.Getenv("CONFIG_FILE"), "path to the nonsecret YAML config file")
	issuer := fs.String("issuer", "", "the OIDC issuer of the sessions to revoke (required)")
	subject := fs.String("subject", "", "the OIDC subject of the sessions to revoke (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *issuer == "" {
		return fmt.Errorf("revoke-admin-session: -issuer is required")
	}
	if *subject == "" {
		return fmt.Errorf("revoke-admin-session: -subject is required")
	}

	cfg, err := config.Load(*configFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL_FILE is not set (see -config or the env var)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	count, err := db.RevokeAdminSessionsByIssuerSubject(ctx, *issuer, *subject)
	if err != nil {
		return fmt.Errorf("revoking admin sessions: %w", err)
	}

	fmt.Printf("revoked %d session(s) for issuer=%s subject=%s\n", count, *issuer, *subject)
	return nil
}

// runPurgeAuditLog deletes audit_events older than -max-age (spec
// section 12: "audit 365 days"). This is a separate operator command,
// not one of cmd/server's own background retention jobs, because only
// the app_maintenance database role may delete audit_events (spec
// section 11, control 10, enforced by migration 000012's grants) --
// -config here must point at a maintenance-role connection, the same
// way migrate-up needs a privileged one. Run it periodically (e.g. a
// daily cron/Swarm job -- see docs/runbooks).
func runPurgeAuditLog(args []string) error {
	fs := flag.NewFlagSet("purge-audit-log", flag.ContinueOnError)
	configFile := fs.String("config", os.Getenv("CONFIG_FILE"), "path to the nonsecret YAML config file")
	maxAge := fs.Duration("max-age", 365*24*time.Hour, "delete audit events older than this")
	batchSize := fs.Int("batch-size", 1000, "rows deleted per batch")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL_FILE is not set (see -config or the env var)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	total := 0
	for {
		n, err := db.PurgeOldAuditEvents(ctx, *maxAge, *batchSize)
		if err != nil {
			return fmt.Errorf("purging audit log: %w", err)
		}
		total += n
		if n < *batchSize {
			break
		}
	}

	fmt.Printf("purge-audit-log: deleted %d audit event(s) older than %s\n", total, *maxAge)
	return nil
}
