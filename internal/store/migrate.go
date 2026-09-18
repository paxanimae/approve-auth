package store

import (
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/frid-iks/approve-auth/migrations"
)

func newMigrator(databaseURL string) (*migrate.Migrate, error) {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("store: loading embedded migrations: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("store: initializing migrator: %w", err)
	}
	return m, nil
}

// MigrateUp applies every pending migration. golang-migrate holds a
// Postgres advisory lock for the duration of the run, so this is safe to
// call from multiple replicas racing on startup (spec section 13: "run a
// one-off, locked migration step").
func MigrateUp(databaseURL string) error {
	m, err := newMigrator(databaseURL)
	if err != nil {
		return err
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("store: migrate up: %w", err)
	}
	return nil
}

// MigrateDown reverses every applied migration. For tests and local
// development only -- production rollback is restore-based (docs/runbooks).
func MigrateDown(databaseURL string) error {
	m, err := newMigrator(databaseURL)
	if err != nil {
		return err
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Down(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("store: migrate down: %w", err)
	}
	return nil
}
