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
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/frid-iks/traefik-manual-proxy/internal/authz"
	"github.com/frid-iks/traefik-manual-proxy/internal/config"
	"github.com/frid-iks/traefik-manual-proxy/internal/enrollment"
	"github.com/frid-iks/traefik-manual-proxy/internal/httpserver"
	"github.com/frid-iks/traefik-manual-proxy/internal/store"
)

const shutdownGrace = 30 * time.Second

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

	authzService := authz.New(db)
	enrollmentService := enrollment.New(db, enrollment.Config{
		RequestTTL:                     cfg.RequestTTL.Std(),
		ClaimTTL:                       cfg.ClaimTTL.Std(),
		ClaimRetryTTL:                  cfg.ClaimRetryTTL.Std(),
		CredentialMaxAge:               cfg.CredentialMaxAge.Std(),
		ClaimEncryptionKey:             cfg.ClaimEncryptionKey,
		ClaimEncryptionKeyID:           cfg.ClaimEncryptionKeyID,
		PendingRequestsPerHourPerAppIP: cfg.RateLimits.PendingRequestsPerHourPerAppIP,
	})

	servers := []*http.Server{
		{Addr: cfg.PublicAddr, Handler: httpserver.NewPublicMux(enrollmentService, authzService, cfg.RequestTTL.Std(), cfg.CredentialMaxAge.Std(), cfg.AuthDecisionTimeout.Std())},
		{Addr: cfg.AdminAddr, Handler: httpserver.NewAdminMux()},
		{Addr: cfg.AuthAddr, Handler: httpserver.NewAuthMux(authzService, cfg.AuthDecisionTimeout.Std()), TLSConfig: authTLSConfig},
		{Addr: cfg.OpsAddr, Handler: httpserver.NewOpsMux()},
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
