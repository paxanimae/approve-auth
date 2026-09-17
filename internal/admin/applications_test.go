package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/traefik-manual-proxy/internal/admin"
	"github.com/frid-iks/traefik-manual-proxy/internal/store"
)

func openService(t *testing.T) (*store.DB, *admin.Service) {
	t.Helper()
	dbURL := skipIfNoDB(t)
	ctx := context.Background()

	db, err := store.Open(ctx, dbURL)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(db.Close)
	return db, admin.New(db, testConfig())
}

func cleanupApplication(t *testing.T, db *store.DB, ctx context.Context, appID uuid.UUID) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(ctx, `DELETE FROM authorizations WHERE application_id = $1`, appID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM approval_requests WHERE application_id = $1`, appID)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, appID)
	})
}

func TestCreateApplication_UsesConfiguredDefaultsWhenUnset(t *testing.T) {
	db, svc := openService(t)
	ctx := context.Background()

	app, err := svc.CreateApplication(ctx, admin.CreateApplicationInput{
		Hostname: "admin-create-" + randomSuffix(t) + ".example.test", DisplayName: "Create Test",
	})
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	cleanupApplication(t, db, ctx, app.ID)

	if got, want := time.Duration(app.DefaultDurationSeconds)*time.Second, 30*24*time.Hour; got != want {
		t.Errorf("DefaultDurationSeconds = %s, want %s (config default)", got, want)
	}
	if got, want := time.Duration(app.MaxDurationSeconds)*time.Second, 365*24*time.Hour; got != want {
		t.Errorf("MaxDurationSeconds = %s, want %s (config default)", got, want)
	}
}

func TestCreateApplication_RejectsDuplicateHostname(t *testing.T) {
	db, svc := openService(t)
	ctx := context.Background()
	hostname := "admin-dup-" + randomSuffix(t) + ".example.test"

	first, err := svc.CreateApplication(ctx, admin.CreateApplicationInput{Hostname: hostname, DisplayName: "First"})
	if err != nil {
		t.Fatalf("CreateApplication (first): %v", err)
	}
	cleanupApplication(t, db, ctx, first.ID)

	_, err = svc.CreateApplication(ctx, admin.CreateApplicationInput{Hostname: hostname, DisplayName: "Second"})
	if !errors.Is(err, admin.ErrDuplicateHostname) {
		t.Errorf("CreateApplication (duplicate): got %v, want ErrDuplicateHostname", err)
	}
}

func TestCreateApplication_RejectsInvalidDuration(t *testing.T) {
	_, svc := openService(t)
	ctx := context.Background()

	_, err := svc.CreateApplication(ctx, admin.CreateApplicationInput{
		Hostname: "admin-baddur-" + randomSuffix(t) + ".example.test", DisplayName: "Bad Duration",
		DefaultDuration: 30 * 24 * time.Hour, MaxDuration: 7 * 24 * time.Hour, // default > max
	})
	if !errors.Is(err, admin.ErrInvalidDuration) {
		t.Errorf("CreateApplication (default > max): got %v, want ErrInvalidDuration", err)
	}
}

func TestUpdateApplication_PartialUpdateAndConflict(t *testing.T) {
	db, svc := openService(t)
	ctx := context.Background()

	app, err := svc.CreateApplication(ctx, admin.CreateApplicationInput{
		Hostname: "admin-update-" + randomSuffix(t) + ".example.test", DisplayName: "Original",
	})
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	cleanupApplication(t, db, ctx, app.ID)

	newName := "Updated Name"
	updated, err := svc.UpdateApplication(ctx, admin.UpdateApplicationInput{
		ApplicationID: app.ID.String(), ExpectedVersion: app.Version, DisplayName: &newName, UpdatedBy: "admin@example.test",
	})
	if err != nil {
		t.Fatalf("UpdateApplication: %v", err)
	}
	if updated.DisplayName != "Updated Name" {
		t.Errorf("DisplayName = %q, want Updated Name", updated.DisplayName)
	}

	_, err = svc.UpdateApplication(ctx, admin.UpdateApplicationInput{
		ApplicationID: app.ID.String(), ExpectedVersion: app.Version, DisplayName: &newName, UpdatedBy: "admin@example.test",
	})
	if !errors.Is(err, admin.ErrConflict) {
		t.Errorf("UpdateApplication (stale version): got %v, want ErrConflict", err)
	}
}

func TestUpdateApplication_RejectsInvalidDuration(t *testing.T) {
	db, svc := openService(t)
	ctx := context.Background()

	app, err := svc.CreateApplication(ctx, admin.CreateApplicationInput{
		Hostname: "admin-updatedur-" + randomSuffix(t) + ".example.test", DisplayName: "Original",
		DefaultDuration: 30 * 24 * time.Hour, MaxDuration: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	cleanupApplication(t, db, ctx, app.ID)

	newMax := 7 * 24 * time.Hour // below the existing default_duration
	_, err = svc.UpdateApplication(ctx, admin.UpdateApplicationInput{
		ApplicationID: app.ID.String(), ExpectedVersion: app.Version, MaxDuration: &newMax, UpdatedBy: "admin@example.test",
	})
	if !errors.Is(err, admin.ErrInvalidDuration) {
		t.Errorf("UpdateApplication (max below existing default): got %v, want ErrInvalidDuration", err)
	}
}

func TestDisableAndEnableApplication(t *testing.T) {
	db, svc := openService(t)
	ctx := context.Background()

	app, err := svc.CreateApplication(ctx, admin.CreateApplicationInput{
		Hostname: "admin-disable-" + randomSuffix(t) + ".example.test", DisplayName: "Disable Test",
	})
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	cleanupApplication(t, db, ctx, app.ID)

	result, err := svc.DisableApplication(ctx, admin.DisableApplicationInput{
		ApplicationID: app.ID.String(), ExpectedVersion: app.Version, Reason: "test", DisabledBy: "admin@example.test",
	})
	if err != nil {
		t.Fatalf("DisableApplication: %v", err)
	}
	if result.Application.Enabled {
		t.Error("application should be disabled")
	}
	if result.CanceledRequests != 0 || result.RevokedAuthorizations != 0 {
		t.Errorf("expected no affected rows on a fresh application, got canceled=%d revoked=%d", result.CanceledRequests, result.RevokedAuthorizations)
	}

	_, err = svc.DisableApplication(ctx, admin.DisableApplicationInput{
		ApplicationID: app.ID.String(), ExpectedVersion: app.Version, Reason: "again", DisabledBy: "admin@example.test",
	})
	if !errors.Is(err, admin.ErrConflict) {
		t.Errorf("DisableApplication (stale version): got %v, want ErrConflict", err)
	}

	enabled, err := svc.EnableApplication(ctx, admin.EnableApplicationInput{
		ApplicationID: app.ID.String(), ExpectedVersion: result.Application.Version, EnabledBy: "admin@example.test",
	})
	if err != nil {
		t.Fatalf("EnableApplication: %v", err)
	}
	if !enabled.Enabled {
		t.Error("application should be enabled again")
	}
}

