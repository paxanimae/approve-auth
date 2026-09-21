package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/frid-iks/approve-auth/internal/store"
)

// withGlobalSettingsRestore snapshots global_settings before the test
// runs and restores every field afterward -- this is a genuine
// singleton row (migration 000019), shared across this whole test
// binary (and the live dev stack, if pointed at the same database),
// so any test that calls UpdateGlobalSettings must put it back.
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
		contactInfo := strFromPtr(original.ContactInfo)
		notifyEmailFrom := strFromPtr(original.NotifyEmailFrom)
		notifyDefaultEmail := strFromPtr(original.NotifyDefaultEmail)
		notifyDefaultWebhookURL := strFromPtr(original.NotifyDefaultWebhookURL)
		revokeIPChanged, revokeUAChanged, revokeInactivity := original.RevokePolicyIPChanged, original.RevokePolicyUserAgentChanged, original.RevokePolicyInactivityExceeded
		threshold := original.RevocationInactivityThreshold
		_, _ = db.UpdateGlobalSettings(ctx, current.Version, store.UpdateGlobalSettingsParams{
			ContactInfo: &contactInfo, NotifyEmailFrom: &notifyEmailFrom, NotifyDefaultEmail: &notifyDefaultEmail, NotifyDefaultWebhookURL: &notifyDefaultWebhookURL,
			RevokePolicyIPChanged: &revokeIPChanged, RevokePolicyUserAgentChanged: &revokeUAChanged,
			RevokePolicyInactivityExceeded: &revokeInactivity, RevocationInactivityThreshold: &threshold,
		}, "test")
	})
}

func strFromPtr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func TestGetGlobalSettings_SeededDefaults(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

	settings, err := db.GetGlobalSettings(ctx)
	if err != nil {
		t.Fatalf("GetGlobalSettings: %v", err)
	}
	if settings.ContactInfo != nil || settings.NotifyEmailFrom != nil || settings.NotifyDefaultEmail != nil || settings.NotifyDefaultWebhookURL != nil {
		t.Errorf("nullable fields should start unset, got %+v", settings)
	}
	if settings.RevokePolicyIPChanged == "" || settings.RevokePolicyUserAgentChanged == "" || settings.RevokePolicyInactivityExceeded == "" {
		t.Errorf("revoke policy fields should always have a real default action, got %+v", settings)
	}
	if settings.RevocationInactivityThreshold <= 0 {
		t.Errorf("RevocationInactivityThreshold = %s, want a positive seeded default", settings.RevocationInactivityThreshold)
	}
	if settings.Version == 0 {
		t.Error("Version should start at 1, not the zero value")
	}
}

func TestUpdateGlobalSettings_PartialUpdateAndConflict(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	withGlobalSettingsRestore(t, db, ctx)

	original, err := db.GetGlobalSettings(ctx)
	if err != nil {
		t.Fatalf("GetGlobalSettings: %v", err)
	}

	newContactInfo := "IT helpdesk: it@example.test"
	updated, err := db.UpdateGlobalSettings(ctx, original.Version, store.UpdateGlobalSettingsParams{ContactInfo: &newContactInfo}, "admin@example.test")
	if err != nil {
		t.Fatalf("UpdateGlobalSettings: %v", err)
	}
	if updated.ContactInfo == nil || *updated.ContactInfo != newContactInfo {
		t.Errorf("ContactInfo = %v, want %q", updated.ContactInfo, newContactInfo)
	}
	if updated.RevokePolicyIPChanged != original.RevokePolicyIPChanged {
		t.Errorf("RevokePolicyIPChanged = %q, want it left unchanged at %q (not passed in this update)", updated.RevokePolicyIPChanged, original.RevokePolicyIPChanged)
	}
	if updated.Version != original.Version+1 {
		t.Errorf("Version = %d, want %d", updated.Version, original.Version+1)
	}

	// A second update against the now-stale original.Version must
	// conflict rather than silently overwrite the update above.
	otherContactInfo := "should not apply"
	_, err = db.UpdateGlobalSettings(ctx, original.Version, store.UpdateGlobalSettingsParams{ContactInfo: &otherContactInfo}, "admin@example.test")
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("UpdateGlobalSettings (stale version): got %v, want ErrConflict", err)
	}
}

func TestUpdateGlobalSettings_EmptyStringClearsNullableField(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	withGlobalSettingsRestore(t, db, ctx)

	original, err := db.GetGlobalSettings(ctx)
	if err != nil {
		t.Fatalf("GetGlobalSettings: %v", err)
	}

	set := "ops@example.test"
	settings, err := db.UpdateGlobalSettings(ctx, original.Version, store.UpdateGlobalSettingsParams{NotifyDefaultEmail: &set}, "admin@example.test")
	if err != nil {
		t.Fatalf("UpdateGlobalSettings (set): %v", err)
	}
	if settings.NotifyDefaultEmail == nil || *settings.NotifyDefaultEmail != set {
		t.Fatalf("NotifyDefaultEmail = %v, want %q", settings.NotifyDefaultEmail, set)
	}

	cleared := ""
	settings, err = db.UpdateGlobalSettings(ctx, settings.Version, store.UpdateGlobalSettingsParams{NotifyDefaultEmail: &cleared}, "admin@example.test")
	if err != nil {
		t.Fatalf("UpdateGlobalSettings (clear): %v", err)
	}
	if settings.NotifyDefaultEmail != nil {
		t.Errorf("NotifyDefaultEmail after clearing with \"\" = %v, want nil", *settings.NotifyDefaultEmail)
	}
}

func TestUpdateGlobalSettings_RevokePolicyAndThreshold(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	withGlobalSettingsRestore(t, db, ctx)

	original, err := db.GetGlobalSettings(ctx)
	if err != nil {
		t.Fatalf("GetGlobalSettings: %v", err)
	}

	action := "revoke"
	threshold := 45 * 24 * time.Hour
	settings, err := db.UpdateGlobalSettings(ctx, original.Version, store.UpdateGlobalSettingsParams{
		RevokePolicyIPChanged: &action, RevocationInactivityThreshold: &threshold,
	}, "admin@example.test")
	if err != nil {
		t.Fatalf("UpdateGlobalSettings: %v", err)
	}
	if settings.RevokePolicyIPChanged != "revoke" {
		t.Errorf("RevokePolicyIPChanged = %q, want revoke", settings.RevokePolicyIPChanged)
	}
	if settings.RevocationInactivityThreshold != threshold {
		t.Errorf("RevocationInactivityThreshold = %s, want %s", settings.RevocationInactivityThreshold, threshold)
	}
}

func TestUpdateGlobalSettings_RecordsAuditEvent(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")
	withGlobalSettingsRestore(t, db, ctx)

	original, err := db.GetGlobalSettings(ctx)
	if err != nil {
		t.Fatalf("GetGlobalSettings: %v", err)
	}
	newContactInfo := "audit trail check"
	if _, err := db.UpdateGlobalSettings(ctx, original.Version, store.UpdateGlobalSettingsParams{ContactInfo: &newContactInfo}, "audit-tester@example.test"); err != nil {
		t.Fatalf("UpdateGlobalSettings: %v", err)
	}

	events, err := db.ListAuditEvents(ctx, store.ListAuditEventsParams{Action: "global_settings.updated", Limit: 5})
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	found := false
	for _, e := range events {
		if e.ActorSubject != nil && *e.ActorSubject == "audit-tester@example.test" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a global_settings.updated audit event recorded for this update")
	}
}
