package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/frid-iks/approve-auth/internal/admin"
	"github.com/frid-iks/approve-auth/internal/store"
)

// withGlobalSettingsRestore is this package's own copy of the store
// package's helper of the same name -- restores the global_settings
// singleton row (migration 000019) after a test mutates it, since
// it's shared across the whole TEST_DATABASE_URL-pointed database.
func withGlobalSettingsRestore(t *testing.T, db *store.DB, ctx context.Context) {
	t.Helper()
	original, err := db.GetGlobalSettings(ctx)
	if err != nil {
		t.Fatalf("GetGlobalSettings: %v", err)
	}
	t.Cleanup(func() {
		current, err := db.GetGlobalSettings(ctx)
		if err != nil {
			return
		}
		strOrEmpty := func(p *string) string {
			if p == nil {
				return ""
			}
			return *p
		}
		contactInfo := strOrEmpty(original.ContactInfo)
		notifyEmailFrom := strOrEmpty(original.NotifyEmailFrom)
		notifyDefaultEmail := strOrEmpty(original.NotifyDefaultEmail)
		notifyDefaultWebhookURL := strOrEmpty(original.NotifyDefaultWebhookURL)
		threshold := original.RevocationInactivityThreshold
		_, _ = db.UpdateGlobalSettings(ctx, current.Version, store.UpdateGlobalSettingsParams{
			ContactInfo: &contactInfo, NotifyEmailFrom: &notifyEmailFrom, NotifyDefaultEmail: &notifyDefaultEmail, NotifyDefaultWebhookURL: &notifyDefaultWebhookURL,
			RevokePolicyIPChanged: &original.RevokePolicyIPChanged, RevokePolicyUserAgentChanged: &original.RevokePolicyUserAgentChanged,
			RevokePolicyInactivityExceeded: &original.RevokePolicyInactivityExceeded, RevocationInactivityThreshold: &threshold,
		}, "test")
	})
}

func openStoreForSettings(t *testing.T) (*store.DB, *admin.Service) {
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

func TestUpdateGlobalSettings_PartialUpdateAndConflict(t *testing.T) {
	db, svc := openStoreForSettings(t)
	ctx := context.Background()
	withGlobalSettingsRestore(t, db, ctx)

	original, err := db.GetGlobalSettings(ctx)
	if err != nil {
		t.Fatalf("GetGlobalSettings: %v", err)
	}

	newContactInfo := "IT helpdesk: it@example.test"
	updated, err := svc.UpdateGlobalSettings(ctx, admin.UpdateGlobalSettingsInput{
		ExpectedVersion: original.Version, ContactInfo: &newContactInfo, UpdatedBy: "admin@example.test",
	})
	if err != nil {
		t.Fatalf("UpdateGlobalSettings: %v", err)
	}
	if updated.ContactInfo == nil || *updated.ContactInfo != newContactInfo {
		t.Errorf("ContactInfo = %v, want %q", updated.ContactInfo, newContactInfo)
	}

	_, err = svc.UpdateGlobalSettings(ctx, admin.UpdateGlobalSettingsInput{
		ExpectedVersion: original.Version, ContactInfo: &newContactInfo, UpdatedBy: "admin@example.test",
	})
	if !errors.Is(err, admin.ErrConflict) {
		t.Errorf("UpdateGlobalSettings (stale version): got %v, want ErrConflict", err)
	}
}

func TestUpdateGlobalSettings_RejectsNonPositiveThreshold(t *testing.T) {
	db, svc := openStoreForSettings(t)
	ctx := context.Background()
	withGlobalSettingsRestore(t, db, ctx)

	original, err := db.GetGlobalSettings(ctx)
	if err != nil {
		t.Fatalf("GetGlobalSettings: %v", err)
	}

	zero := time.Duration(0)
	_, err = svc.UpdateGlobalSettings(ctx, admin.UpdateGlobalSettingsInput{
		ExpectedVersion: original.Version, RevocationInactivityThreshold: &zero, UpdatedBy: "admin@example.test",
	})
	if !errors.Is(err, admin.ErrInvalidRevocationThreshold) {
		t.Errorf("UpdateGlobalSettings (zero threshold): got %v, want ErrInvalidRevocationThreshold", err)
	}

	negative := -time.Hour
	_, err = svc.UpdateGlobalSettings(ctx, admin.UpdateGlobalSettingsInput{
		ExpectedVersion: original.Version, RevocationInactivityThreshold: &negative, UpdatedBy: "admin@example.test",
	})
	if !errors.Is(err, admin.ErrInvalidRevocationThreshold) {
		t.Errorf("UpdateGlobalSettings (negative threshold): got %v, want ErrInvalidRevocationThreshold", err)
	}
}
