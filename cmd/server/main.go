// Command server is the single binary that exposes all four listeners
// (Public, Admin, Authorization, Ops) described in spec section 2.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/frid-iks/approve-auth/internal/admin"
	"github.com/frid-iks/approve-auth/internal/adminsession"
	"github.com/frid-iks/approve-auth/internal/authz"
	"github.com/frid-iks/approve-auth/internal/config"
	"github.com/frid-iks/approve-auth/internal/enrollment"
	"github.com/frid-iks/approve-auth/internal/geoip"
	"github.com/frid-iks/approve-auth/internal/httpserver"
	"github.com/frid-iks/approve-auth/internal/metrics"
	"github.com/frid-iks/approve-auth/internal/notify"
	"github.com/frid-iks/approve-auth/internal/oidc"
	"github.com/frid-iks/approve-auth/internal/revokepolicy"
	"github.com/frid-iks/approve-auth/internal/store"
	"github.com/frid-iks/approve-auth/internal/version"
	"github.com/frid-iks/approve-auth/internal/worker"
)

const shutdownGrace = 30 * time.Second

// oidcTransactionTTL is spec section 9's fixed 10-minute OIDC transient-
// state expiry -- unlike ADMIN_IDLE_TTL/ADMIN_ABSOLUTE_TTL, section 14's
// configuration table does not list this as an operator-tunable setting.
const oidcTransactionTTL = 10 * time.Minute

// overviewRecentWindow bounds GET /overview's "revoked/expired recently"
// count (spec section 9 names the count but not its exact window).
const overviewRecentWindow = 24 * time.Hour

// Listener timeout defaults (endpoint-review.md F1: "none of the four
// http.Server{} structs ... set ReadTimeout/ReadHeaderTimeout/
// IdleTimeout"). Not operator-tunable settings -- like
// oidcTransactionTTL, nothing in the product spec calls for tuning
// these; they exist purely so a slow-header or slow-body caller can't
// hold a connection (and its goroutine) open indefinitely regardless of
// what any reverse proxy in front of a listener does or doesn't
// enforce. writeTimeout is generous enough to cover the slowest normal
// response this service ever produces (an admin audit-log CSV export)
// without meaningfully bounding a genuinely slow client.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 120 * time.Second
)

// workerTickInterval governs how often each retention/cleanup job runs
// (internal/worker). Not one of spec section 14's operator-tunable
// settings, only "bounded batches" is specified -- five minutes keeps
// an ordinary backlog small enough that "bounded" never matters.
const workerTickInterval = 5 * time.Minute

// notificationDeliveryBatchSize bounds one delivery-job tick the same
// way internal/worker's own batchSize bounds its retention jobs --
// notifications aren't spec-mandated, so there's no spec batch size to
// match, just the same "bounded, not unbounded" principle.
const notificationDeliveryBatchSize = 200

// inactivityPolicyBatchSize is EnforceInactivityPolicy's own per-tick
// bound, same "bounded, not unbounded" principle as
// notificationDeliveryBatchSize -- revocation policy isn't spec-
// mandated either, so there's no spec batch size to match.
const inactivityPolicyBatchSize = 200

// messageRedactionBatchSize is RedactOldRequestMessages' own per-tick
// bound (endpoint-review.md F5), same "bounded, not unbounded"
// principle as inactivityPolicyBatchSize above.
const messageRedactionBatchSize = 200

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	configFile := flag.String("config", os.Getenv("CONFIG_FILE"), "path to the nonsecret YAML config file")
	flag.Parse()

	cfg, err := config.Load(*configFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config, refusing to start:\n%w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()
	if err := db.Ping(ctx); err != nil {
		return fmt.Errorf("database not reachable at startup: %w", err)
	}
	ready, err := db.SchemaReady(ctx)
	if err != nil {
		return fmt.Errorf("checking schema readiness: %w", err)
	}
	if !ready {
		return fmt.Errorf("schema not migrated -- run `admin migrate-up` with a privileged database connection first")
	}

	authTLSConfig, err := httpserver.AuthTLSConfig(cfg.AuthTLSCertFile, cfg.AuthTLSKeyFile, cfg.AuthClientCAFile, cfg.AuthAllowedClientIdentities)
	if err != nil {
		return fmt.Errorf("building authorization listener TLS config: %w", err)
	}

	// geoipLookup stays Noop{} (every lookup reports "unresolved") when
	// no database is configured -- this feature is opt-in, not required.
	var geoipLookup geoip.Lookup = geoip.Noop{}
	if cfg.GeoIPDatabasePath != "" {
		mm, err := geoip.Open(cfg.GeoIPDatabasePath)
		if err != nil {
			return fmt.Errorf("opening GeoIP database at %s: %w", cfg.GeoIPDatabasePath, err)
		}
		defer mm.Close()
		geoipLookup = mm
	}

	authzService := authz.New(db)
	enrollmentService := enrollment.New(db, geoipLookup, enrollment.Config{
		RequestTTL:                     cfg.RequestTTL.Std(),
		ClaimTTL:                       cfg.ClaimTTL.Std(),
		ClaimRetryTTL:                  cfg.ClaimRetryTTL.Std(),
		CredentialMaxAge:               cfg.CredentialMaxAge.Std(),
		ClaimEncryptionKey:             cfg.ClaimEncryptionKey,
		ClaimEncryptionKeyID:           cfg.ClaimEncryptionKeyID,
		PendingRequestsPerHourPerAppIP: cfg.RateLimits.PendingRequestsPerHourPerAppIP,
		BootstrapPerMinutePerIP:        cfg.RateLimits.BootstrapPerMinutePerIP,
		StatusPerMinutePerPendingProof: cfg.RateLimits.StatusPerMinutePerPendingProof,
		GlobalEnrollmentPerHour:        cfg.RateLimits.GlobalEnrollmentPerHour,
	})

	adminHost, err := adminOriginHost(cfg.AdminOrigin)
	if err != nil {
		return fmt.Errorf("invalid admin_origin: %w", err)
	}
	var adminSessions httpserver.AdminSessions
	switch cfg.AdminAuthMode {
	case "anonymous":
		// No login at all -- some other mechanism in front of the admin
		// listener (VPN, SSO reverse proxy, network ACLs) is solely
		// responsible for deciding who reaches it. See
		// internal/adminsession.Anonymous for what this does and does
		// not weaken.
		adminSessions, err = adminsession.NewAnonymous(cfg.AdminAnonymousSubject, cfg.AdminAnonymousDisplayName, cfg.AdminAnonymousRole)
		if err != nil {
			return fmt.Errorf("building anonymous admin identity: %w", err)
		}
	default:
		oidcClient, err := oidc.NewClient(ctx, cfg.OIDCIssuer, cfg.OIDCClientID, cfg.OIDCClientSecret, cfg.AdminOrigin+"/auth/callback")
		if err != nil {
			return fmt.Errorf("building OIDC client: %w", err)
		}
		adminSessions = adminsession.New(db, oidcClient, adminsession.Config{
			OIDCAdminGroups:    cfg.OIDCAdminGroups,
			OIDCViewerGroups:   cfg.OIDCViewerGroups,
			IdleTTL:            cfg.AdminIdleTTL.Std(),
			AbsoluteTTL:        cfg.AdminAbsoluteTTL.Std(),
			TransactionTTL:     oidcTransactionTTL,
			StateEncryptionKey: cfg.OIDCStateEncryptionKey,
		})
	}
	adminActions := admin.New(db, admin.Config{
		DefaultAuthorizationDuration: cfg.DefaultAuthorizationDuration.Std(),
		MaxAuthorizationDuration:     cfg.MaxAuthorizationDuration.Std(),
		ClaimTTL:                     cfg.ClaimTTL.Std(),
	})

	jobs := worker.Jobs(db, worker.Config{
		ResolvedRequestsRetention: cfg.Retention.ResolvedRequests.Std(),
		IPAndUserAgentRetention:   cfg.Retention.IPAndUserAgent.Std(),
		ReturnPathsRetention:      cfg.Retention.ReturnPaths.Std(),
		NotificationsRetention:    cfg.Retention.Notifications.Std(),
		TickInterval:              workerTickInterval,
	})
	jobs = append(jobs, worker.Job{
		// Reads global_settings fresh every tick (not closed over at
		// startup) -- the whole point of moving these off static
		// config is that an administrator's edit via the Settings
		// page takes effect on the next tick, no restart needed.
		Name: "enforce_inactivity_policy", Interval: workerTickInterval,
		Run: func(ctx context.Context) error {
			settings, err := db.GetGlobalSettings(ctx)
			if err != nil {
				return fmt.Errorf("enforce_inactivity_policy: loading global settings: %w", err)
			}
			_, err = db.EnforceInactivityPolicy(ctx, revokepolicy.Action(settings.RevokePolicyInactivityExceeded), settings.RevocationInactivityThreshold, inactivityPolicyBatchSize)
			return err
		},
	})
	jobs = append(jobs, worker.Job{
		// endpoint-review.md F5: message_retention_seconds is a
		// business rule (migration 000022), read fresh every tick the
		// same way enforce_inactivity_policy reads its own settings
		// above, not baked into worker.Config's static durations.
		Name: "redact_old_request_messages", Interval: workerTickInterval,
		Run: func(ctx context.Context) error {
			settings, err := db.GetGlobalSettings(ctx)
			if err != nil {
				return fmt.Errorf("redact_old_request_messages: loading global settings: %w", err)
			}
			_, err = db.RedactOldRequestMessages(ctx, settings.MessageRetention, messageRedactionBatchSize)
			return err
		},
	})

	notifier := notify.New(notify.Config{
		SMTPHost: cfg.NotifySMTPHost, SMTPPort: cfg.NotifySMTPPort, SMTPUsername: cfg.NotifySMTPUsername, SMTPPassword: cfg.NotifySMTPPassword,
		WebhookSecret: cfg.NotifyWebhookSecret, AdminOrigin: cfg.AdminOrigin,
	})
	jobs = append(jobs, worker.Job{
		Name: "deliver_notifications", Interval: workerTickInterval,
		Run: func(ctx context.Context) error {
			_, err := notifier.DeliverPending(ctx, db, notificationDeliveryBatchSize)
			return err
		},
	})

	retentionWorker := worker.New(db, jobs)
	retentionWorker.Start(ctx)
	go reportOverviewGauges(ctx, db, cfg.ExpiringSoonWindow.Std())

	servers := []*http.Server{
		{Addr: cfg.PublicAddr, Handler: httpserver.NewPublicMux(enrollmentService, authzService, cfg.RequestTTL.Std(), cfg.CredentialMaxAge.Std(), cfg.AuthDecisionTimeout.Std(), cfg.TrustedTraefikCIDRs, cfg.AdminOrigin)},
		{Addr: cfg.AdminAddr, Handler: httpserver.NewAdminMux(adminSessions, adminActions, db, adminHost, cfg.AdminAbsoluteTTL.Std(), cfg.ExpiringSoonWindow.Std(), overviewRecentWindow, cfg.DefaultAuthorizationDuration.Std(), cfg.MaxAuthorizationDuration.Std(), cfg.AuthDecisionTimeout.Std(), version.Version, cfg.InstanceName)},
		{Addr: cfg.AuthAddr, Handler: httpserver.NewAuthMux(authzService, cfg.AuthDecisionTimeout.Std()), TLSConfig: authTLSConfig},
		{Addr: cfg.OpsAddr, Handler: httpserver.NewOpsMux(db)},
	}
	for _, srv := range servers {
		srv.ReadHeaderTimeout = readHeaderTimeout
		srv.ReadTimeout = readTimeout
		srv.WriteTimeout = writeTimeout
		srv.IdleTimeout = idleTimeout
	}

	errCh := make(chan error, len(servers))
	for _, srv := range servers {
		srv := srv
		go func() {
			var err error
			if srv.TLSConfig != nil {
				err = srv.ListenAndServeTLS("", "")
			} else {
				err = srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("listener %s: %w", srv.Addr, err)
			}
		}()
	}
	log.Printf("listening: public=%s admin=%s auth=%s ops=%s", cfg.PublicAddr, cfg.AdminAddr, cfg.AuthAddr, cfg.OpsAddr)
	metrics.Ready.Set(1)
	defer metrics.Ready.Set(0)

	select {
	case <-ctx.Done():
		log.Print("shutting down")
	case err := <-errCh:
		log.Printf("listener error, shutting down: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	var wg sync.WaitGroup
	for _, srv := range servers {
		srv := srv
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				log.Printf("shutting down %s: %v", srv.Addr, err)
			}
		}()
	}
	wg.Wait()

	return nil
}

// reportOverviewGauges periodically reflects store.GetOverviewCounts
// into the pending/active/expiring-soon gauges spec section 15 asks for
// ("active/pending/expiring counts"), reusing the same query the admin
// API's GET /overview already runs -- this is a metrics convenience,
// not a new counting mechanism.
func reportOverviewGauges(ctx context.Context, db *store.DB, expiringSoonWindow time.Duration) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		counts, err := db.GetOverviewCounts(ctx, expiringSoonWindow, overviewRecentWindow)
		if err == nil {
			metrics.PendingRequests.Set(float64(counts.Pending))
			metrics.ActiveAuthorizations.Set(float64(counts.Active))
			metrics.ExpiringSoonAuthorizations.Set(float64(counts.ExpiringSoon))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// adminOriginHost extracts just the hostname from the configured
// ADMIN_ORIGIN (e.g. "https://approval-admin.example.com" ->
// "approval-admin.example.com"), matching the port-stripped, lowercased
// form httpserver.requestHostname derives from an incoming request's
// Host header.
func adminOriginHost(adminOrigin string) (string, error) {
	u, err := url.Parse(adminOrigin)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("could not parse a hostname from %q", adminOrigin)
	}
	return strings.ToLower(u.Hostname()), nil
}
