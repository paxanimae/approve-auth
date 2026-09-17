package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// CreateApplication registers a new application. hostname is lowercased
// before insert -- the migration's CHECK constraint would reject a mixed-
// case value outright, but normalizing here gives a clearer error path
// than a raw constraint violation for the common case of a caller not
// having lowercased it themselves.
func (db *DB) CreateApplication(ctx context.Context, hostname, displayName, description string, defaultDuration, maxDuration time.Duration) (Application, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return Application{}, fmt.Errorf("store: creating application %q: begin: %w", hostname, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var app Application
	err = tx.QueryRow(ctx, `
		INSERT INTO applications (hostname, display_name, description, default_duration_seconds, max_duration_seconds)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, hostname, display_name, description, enabled, default_duration_seconds, max_duration_seconds, created_at, updated_at, archived_at, version`,
		strings.ToLower(hostname), displayName, description,
		int32(defaultDuration.Seconds()), int32(maxDuration.Seconds()),
	).Scan(
		&app.ID, &app.Hostname, &app.DisplayName, &app.Description, &app.Enabled,
		&app.DefaultDurationSeconds, &app.MaxDurationSeconds,
		&app.CreatedAt, &app.UpdatedAt, &app.ArchivedAt, &app.Version,
	)
	if err != nil {
		return Application{}, fmt.Errorf("store: creating application %q: %w", hostname, err)
	}

	// ActorSubject is empty: cmd/admin has no identity system of its own
	// yet (no OIDC integration until Milestone 4) -- still worth an
	// audit row naming the action and the application it created.
	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", Action: "application.created", ApplicationID: &app.ID,
	}); err != nil {
		return Application{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Application{}, fmt.Errorf("store: creating application %q: commit: %w", hostname, err)
	}
	return app, nil
}

// GetApplicationByHostname returns (app, true, nil) if found, (Application{}, false, nil)
// if no application is registered for hostname.
func (db *DB) GetApplicationByHostname(ctx context.Context, hostname string) (Application, bool, error) {
	var app Application
	err := db.Pool.QueryRow(ctx, `
		SELECT id, hostname, display_name, description, enabled, default_duration_seconds, max_duration_seconds, created_at, updated_at, archived_at, version
		FROM applications
		WHERE hostname = $1`, strings.ToLower(hostname),
	).Scan(
		&app.ID, &app.Hostname, &app.DisplayName, &app.Description, &app.Enabled,
		&app.DefaultDurationSeconds, &app.MaxDurationSeconds,
		&app.CreatedAt, &app.UpdatedAt, &app.ArchivedAt, &app.Version,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Application{}, false, nil
	}
	if err != nil {
		return Application{}, false, fmt.Errorf("store: looking up application %q: %w", hostname, err)
	}
	return app, true, nil
}
