package authz_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/authz"
	"github.com/frid-iks/approve-auth/internal/store"
)

type fakeStore struct {
	snapshot    *store.AccessSnapshot
	snapshotErr error

	touchErr    error
	touchCalled bool
	touchedID   uuid.UUID
}

func (f *fakeStore) GetAccessSnapshot(_ context.Context, _ string, _ []byte) (*store.AccessSnapshot, error) {
	return f.snapshot, f.snapshotErr
}

func (f *fakeStore) TouchLastSeen(_ context.Context, id uuid.UUID, _, _ string) error {
	f.touchCalled = true
	f.touchedID = id
	return f.touchErr
}

// validSnapshot returns a snapshot representing a fully valid access
// grant; each test mutates exactly the field(s) it wants to break.
func validSnapshot() *store.AccessSnapshot {
	appID := uuid.New()
	authID := uuid.New()
	now := time.Now()
	return &store.AccessSnapshot{
		ApplicationID:               appID,
		ApplicationEnabled:          true,
		CredentialFound:             true,
		CredentialApplicationID:     appID,
		CredentialRevoked:           false,
		CredentialAbsoluteExpiresAt: now.Add(365 * 24 * time.Hour),
		AuthorizationID:             authID,
		AuthorizationRevoked:        false,
		AuthorizationActivated:      true,
		AuthorizationExpiresAt:      now.Add(30 * 24 * time.Hour),
		DatabaseNow:                 now,
	}
}

func TestDecide_NoCookiePresented(t *testing.T) {
	fs := &fakeStore{snapshot: validSnapshot()}
	svc := authz.New(fs)

	d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Category != authz.CategoryMissingOrInvalidCredential {
		t.Errorf("Category = %v, want CategoryMissingOrInvalidCredential", d.Category)
	}
	if fs.touchCalled {
		t.Error("TouchLastSeen should not be called when there's no cookie to evaluate")
	}
}

func TestDecide_StoreError(t *testing.T) {
	fs := &fakeStore{snapshotErr: errors.New("boom")}
	svc := authz.New(fs)

	_, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token"})
	if err == nil {
		t.Fatal("Decide: expected an error when the store fails, got nil")
	}
}

func TestDecide_UnknownHost(t *testing.T) {
	fs := &fakeStore{snapshot: nil}
	svc := authz.New(fs)

	d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "unknown.example.test", CookieValue: "token"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Category != authz.CategoryUnknownHost {
		t.Errorf("Category = %v, want CategoryUnknownHost", d.Category)
	}
}

func TestDecide_Allow(t *testing.T) {
	fs := &fakeStore{snapshot: validSnapshot()}
	svc := authz.New(fs)

	d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token", ClientAddr: "203.0.113.1", UserAgent: "test-agent"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Category != authz.CategoryAllow {
		t.Errorf("Category = %v, want CategoryAllow", d.Category)
	}
	if !fs.touchCalled {
		t.Error("TouchLastSeen should be called on allow")
	}
	if fs.touchedID != fs.snapshot.AuthorizationID {
		t.Errorf("TouchLastSeen called with %s, want %s", fs.touchedID, fs.snapshot.AuthorizationID)
	}
}

func TestDecide_AllowDespiteTouchLastSeenFailure(t *testing.T) {
	fs := &fakeStore{snapshot: validSnapshot(), touchErr: errors.New("advisory write failed")}
	svc := authz.New(fs)

	d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token"})
	if err != nil {
		t.Fatalf("Decide: %v (a TouchLastSeen failure must not affect the decision)", err)
	}
	if d.Category != authz.CategoryAllow {
		t.Errorf("Category = %v, want CategoryAllow", d.Category)
	}
}

func TestDecide_DenyBranches(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*store.AccessSnapshot)
		wantCat authz.Category
	}{
		{
			name:    "application disabled",
			mutate:  func(s *store.AccessSnapshot) { s.ApplicationEnabled = false },
			wantCat: authz.CategoryRevokedOrDisabled,
		},
		{
			name:    "credential not found",
			mutate:  func(s *store.AccessSnapshot) { s.CredentialFound = false },
			wantCat: authz.CategoryMissingOrInvalidCredential,
		},
		{
			name:    "credential for a different application",
			mutate:  func(s *store.AccessSnapshot) { s.CredentialApplicationID = uuid.New() },
			wantCat: authz.CategoryMissingOrInvalidCredential,
		},
		{
			name:    "credential revoked",
			mutate:  func(s *store.AccessSnapshot) { s.CredentialRevoked = true },
			wantCat: authz.CategoryRevokedOrDisabled,
		},
		{
			name:    "authorization revoked",
			mutate:  func(s *store.AccessSnapshot) { s.AuthorizationRevoked = true },
			wantCat: authz.CategoryRevokedOrDisabled,
		},
		{
			name:    "authorization not yet activated (unclaimed)",
			mutate:  func(s *store.AccessSnapshot) { s.AuthorizationActivated = false },
			wantCat: authz.CategoryMissingOrInvalidCredential,
		},
		{
			name:    "authorization expired (strictly equal counts as expired)",
			mutate:  func(s *store.AccessSnapshot) { s.AuthorizationExpiresAt = s.DatabaseNow },
			wantCat: authz.CategoryMissingOrInvalidCredential,
		},
		{
			name:    "authorization expiry in the past",
			mutate:  func(s *store.AccessSnapshot) { s.AuthorizationExpiresAt = s.DatabaseNow.Add(-time.Minute) },
			wantCat: authz.CategoryMissingOrInvalidCredential,
		},
		{
			name:    "credential absolute expiry reached",
			mutate:  func(s *store.AccessSnapshot) { s.CredentialAbsoluteExpiresAt = s.DatabaseNow },
			wantCat: authz.CategoryMissingOrInvalidCredential,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := validSnapshot()
			tt.mutate(snap)
			fs := &fakeStore{snapshot: snap}
			svc := authz.New(fs)

			d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token"})
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if d.Category != tt.wantCat {
				t.Errorf("Category = %v, want %v (reason: %s)", d.Category, tt.wantCat, d.Reason)
			}
			if fs.touchCalled {
				t.Error("TouchLastSeen should not be called on a deny")
			}
		})
	}
}
