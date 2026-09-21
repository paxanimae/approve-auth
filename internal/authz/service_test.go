package authz_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paxanimae/approve-auth/internal/authz"
	"github.com/paxanimae/approve-auth/internal/revokepolicy"
	"github.com/paxanimae/approve-auth/internal/store"
)

func ipPtr(s string) *net.IP {
	ip := net.ParseIP(s)
	return &ip
}

func strPtr(s string) *string { return &s }

type fakeStore struct {
	snapshot    *store.AccessSnapshot
	snapshotErr error

	touchErr    error
	touchCalled bool
	touchedID   uuid.UUID

	revokeErr    error
	revokeCalled bool
	revokedID    uuid.UUID
	revokeReason string

	flagErr    error
	flagCalled bool
	flaggedID  uuid.UUID
	flagReason string

	warnErr    error
	warnCalled bool
	warnedID   uuid.UUID
	warnSignal string
}

func (f *fakeStore) GetAccessSnapshot(_ context.Context, _ string, _ []byte) (*store.AccessSnapshot, error) {
	return f.snapshot, f.snapshotErr
}

func (f *fakeStore) TouchLastSeen(_ context.Context, id uuid.UUID, _, _ string) error {
	f.touchCalled = true
	f.touchedID = id
	return f.touchErr
}

func (f *fakeStore) RevokeAuthorization(_ context.Context, id uuid.UUID, _ int32, reason, _ string) error {
	f.revokeCalled = true
	f.revokedID = id
	f.revokeReason = reason
	return f.revokeErr
}

func (f *fakeStore) FlagAuthorizationForReview(_ context.Context, id, _ uuid.UUID, reason string) error {
	f.flagCalled = true
	f.flaggedID = id
	f.flagReason = reason
	return f.flagErr
}

func (f *fakeStore) RecordRevocationPolicyWarning(_ context.Context, id, _ uuid.UUID, signal string) error {
	f.warnCalled = true
	f.warnedID = id
	f.warnSignal = signal
	return f.warnErr
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

// --- Revocation policy: IP/User-Agent change signals ---

func TestDecide_NoSignalOnFirstUse(t *testing.T) {
	// LastSeenIP/LastSeenUserAgent both nil (this credential has never
	// been used before) -- even an aggressive global default must not
	// fire on establishing the baseline.
	snap := validSnapshot()
	snap.RevokePolicyIPChangedGlobal = string(revokepolicy.ActionRevoke)
	snap.RevokePolicyUserAgentChangedGlobal = string(revokepolicy.ActionRevoke)
	fs := &fakeStore{snapshot: snap}
	svc := authz.New(fs)

	d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token", ClientAddr: "203.0.113.1", UserAgent: "first-ever-agent"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Category != authz.CategoryAllow {
		t.Errorf("Category = %v, want CategoryAllow", d.Category)
	}
	if fs.revokeCalled || fs.flagCalled || fs.warnCalled {
		t.Error("no revocation-policy action should fire when establishing the first-use baseline")
	}
}

func TestDecide_NoSignalWhenIPAndUserAgentUnchanged(t *testing.T) {
	snap := validSnapshot()
	snap.LastSeenIP = ipPtr("203.0.113.1")
	snap.LastSeenUserAgent = strPtr("same-agent")
	snap.RevokePolicyIPChangedGlobal = string(revokepolicy.ActionRevoke)
	snap.RevokePolicyUserAgentChangedGlobal = string(revokepolicy.ActionRevoke)
	fs := &fakeStore{snapshot: snap}
	svc := authz.New(fs)

	d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token", ClientAddr: "203.0.113.1", UserAgent: "same-agent"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Category != authz.CategoryAllow {
		t.Errorf("Category = %v, want CategoryAllow", d.Category)
	}
	if fs.revokeCalled {
		t.Error("no revocation-policy action should fire when the IP/UA match what's already on record")
	}
}

func TestDecide_IPChangedRevokesWhenConfigured(t *testing.T) {
	snap := validSnapshot()
	snap.LastSeenIP = ipPtr("203.0.113.1")
	snap.RevokePolicyIPChangedGlobal = string(revokepolicy.ActionRevoke)
	fs := &fakeStore{snapshot: snap}
	svc := authz.New(fs)

	d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token", ClientAddr: "203.0.113.2"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Category != authz.CategoryRevokedOrDisabled {
		t.Errorf("Category = %v, want CategoryRevokedOrDisabled", d.Category)
	}
	if !fs.revokeCalled || fs.revokedID != snap.AuthorizationID {
		t.Errorf("expected RevokeAuthorization to be called for %s, revokeCalled=%v revokedID=%s", snap.AuthorizationID, fs.revokeCalled, fs.revokedID)
	}
	if fs.revokeReason != string(revokepolicy.SignalIPChanged) {
		t.Errorf("revokeReason = %q, want %q", fs.revokeReason, revokepolicy.SignalIPChanged)
	}
	if fs.touchCalled {
		t.Error("TouchLastSeen should not be called once the authorization is revoked in-path")
	}
}

func TestDecide_IPChangedFlagsForReviewWhenConfigured(t *testing.T) {
	snap := validSnapshot()
	snap.LastSeenIP = ipPtr("203.0.113.1")
	snap.RevokePolicyIPChangedGlobal = string(revokepolicy.ActionFlagForReview)
	fs := &fakeStore{snapshot: snap}
	svc := authz.New(fs)

	d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token", ClientAddr: "203.0.113.2"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Category != authz.CategoryAllow {
		t.Errorf("Category = %v, want CategoryAllow (flag_for_review must not deny access)", d.Category)
	}
	if !fs.flagCalled || fs.flaggedID != snap.AuthorizationID {
		t.Errorf("expected FlagAuthorizationForReview to be called for %s, flagCalled=%v flaggedID=%s", snap.AuthorizationID, fs.flagCalled, fs.flaggedID)
	}
	if !fs.touchCalled {
		t.Error("TouchLastSeen should still be called when the outcome stays Allow")
	}
}

func TestDecide_UserAgentChangedWarnsWhenConfigured(t *testing.T) {
	snap := validSnapshot()
	snap.LastSeenUserAgent = strPtr("old-agent")
	snap.RevokePolicyUserAgentChangedGlobal = string(revokepolicy.ActionWarn)
	fs := &fakeStore{snapshot: snap}
	svc := authz.New(fs)

	d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token", UserAgent: "new-agent"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Category != authz.CategoryAllow {
		t.Errorf("Category = %v, want CategoryAllow (warn must not deny access)", d.Category)
	}
	if !fs.warnCalled || fs.warnedID != snap.AuthorizationID {
		t.Errorf("expected RecordRevocationPolicyWarning to be called for %s, warnCalled=%v warnedID=%s", snap.AuthorizationID, fs.warnCalled, fs.warnedID)
	}
	if fs.warnSignal != string(revokepolicy.SignalUserAgentChanged) {
		t.Errorf("warnSignal = %q, want %q", fs.warnSignal, revokepolicy.SignalUserAgentChanged)
	}
}

func TestDecide_SessionOverrideBeatsGlobalDefault(t *testing.T) {
	snap := validSnapshot()
	snap.LastSeenIP = ipPtr("203.0.113.1")
	snap.RevokePolicyIPChangedSession = strPtr(string(revokepolicy.ActionRevoke))
	snap.RevokePolicyIPChangedGlobal = string(revokepolicy.ActionWarn)
	fs := &fakeStore{snapshot: snap}
	svc := authz.New(fs)

	d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token", ClientAddr: "203.0.113.2"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Category != authz.CategoryRevokedOrDisabled {
		t.Errorf("Category = %v, want CategoryRevokedOrDisabled (session override should beat the global warn default)", d.Category)
	}
	if !fs.revokeCalled {
		t.Error("expected RevokeAuthorization to be called")
	}
}

func TestDecide_ApplicationOverrideBeatsGlobalWhenSessionUnset(t *testing.T) {
	snap := validSnapshot()
	snap.LastSeenIP = ipPtr("203.0.113.1")
	snap.RevokePolicyIPChangedApp = strPtr(string(revokepolicy.ActionFlagForReview))
	snap.RevokePolicyIPChangedGlobal = string(revokepolicy.ActionOff)
	fs := &fakeStore{snapshot: snap}
	svc := authz.New(fs)

	d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token", ClientAddr: "203.0.113.2"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Category != authz.CategoryAllow {
		t.Errorf("Category = %v, want CategoryAllow", d.Category)
	}
	if !fs.flagCalled {
		t.Error("expected the application-level override (flag_for_review) to apply since the global default is off")
	}
}

func TestDecide_MostSevereOfTwoFiredSignalsWins(t *testing.T) {
	snap := validSnapshot()
	snap.LastSeenIP = ipPtr("203.0.113.1")
	snap.LastSeenUserAgent = strPtr("old-agent")
	// IP change is only configured to warn; User-Agent change is
	// configured to revoke -- even though IP is usually the more
	// commonly escalated signal, revoke must win because it's the more
	// severe of the two outcomes that actually fired.
	snap.RevokePolicyIPChangedGlobal = string(revokepolicy.ActionWarn)
	snap.RevokePolicyUserAgentChangedGlobal = string(revokepolicy.ActionRevoke)
	fs := &fakeStore{snapshot: snap}
	svc := authz.New(fs)

	d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token", ClientAddr: "203.0.113.2", UserAgent: "new-agent"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Category != authz.CategoryRevokedOrDisabled {
		t.Errorf("Category = %v, want CategoryRevokedOrDisabled", d.Category)
	}
	if fs.revokeReason != string(revokepolicy.SignalUserAgentChanged) {
		t.Errorf("revokeReason = %q, want %q (the more severe of the two fired signals)", fs.revokeReason, revokepolicy.SignalUserAgentChanged)
	}
	if fs.warnCalled {
		t.Error("only the single more severe outcome should apply, not also a warn for the other signal")
	}
}

func TestDecide_RevokeConflictDeniesWithoutPropagatingAnError(t *testing.T) {
	snap := validSnapshot()
	snap.LastSeenIP = ipPtr("203.0.113.1")
	snap.RevokePolicyIPChangedGlobal = string(revokepolicy.ActionRevoke)
	fs := &fakeStore{snapshot: snap, revokeErr: store.ErrConflict}
	svc := authz.New(fs)

	d, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token", ClientAddr: "203.0.113.2"})
	if err != nil {
		t.Fatalf("Decide: %v (a concurrent-change conflict must resolve to Deny, not a hard error)", err)
	}
	if d.Category != authz.CategoryRevokedOrDisabled {
		t.Errorf("Category = %v, want CategoryRevokedOrDisabled", d.Category)
	}
}

func TestDecide_RevokeOtherErrorPropagates(t *testing.T) {
	snap := validSnapshot()
	snap.LastSeenIP = ipPtr("203.0.113.1")
	snap.RevokePolicyIPChangedGlobal = string(revokepolicy.ActionRevoke)
	fs := &fakeStore{snapshot: snap, revokeErr: errors.New("database exploded")}
	svc := authz.New(fs)

	_, err := svc.Decide(context.Background(), authz.AuthRequest{Host: "app.example.test", CookieValue: "token", ClientAddr: "203.0.113.2"})
	if err == nil {
		t.Fatal("Decide: expected a propagated error for a non-conflict revoke failure, got nil")
	}
}
