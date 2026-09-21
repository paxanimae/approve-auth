package authz

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/revokepolicy"
	"github.com/frid-iks/approve-auth/internal/store"
)

// Store is the read/write surface Decide needs. Defined here (not just
// used as *store.DB directly) so tests can substitute a fake and exercise
// every branch of the decision table without a real database.
type Store interface {
	GetAccessSnapshot(ctx context.Context, hostname string, credentialTokenHash []byte) (*store.AccessSnapshot, error)
	TouchLastSeen(ctx context.Context, authorizationID uuid.UUID, clientIP, userAgent string) error

	// RevokeAuthorization/FlagAuthorizationForReview/RecordRevocationPolicyWarning
	// back the revocation-policy "revoke"/"flag_for_review"/"warn"
	// actions (internal/revokepolicy) -- see resolveChangeSignal and
	// its callers in Decide.
	RevokeAuthorization(ctx context.Context, authorizationID uuid.UUID, expectedVersion int32, reason, revokedBy string) error
	FlagAuthorizationForReview(ctx context.Context, authorizationID, applicationID uuid.UUID, reason string) error
	RecordRevocationPolicyWarning(ctx context.Context, authorizationID, applicationID uuid.UUID, signal string) error
}

// revokePolicyActor is the fixed system-actor identity used for every
// revocation-policy-triggered mutation's audit trail -- distinct from
// any real admin subject, and from "system" audit rows written by the
// retention worker (internal/store's own ActorType "system" already
// covers that distinction; this is specifically the revoked_by value
// RevokeAuthorization's audit event records).
const revokePolicyActor = "system:revoke-policy"

type Service struct {
	store Store
}

func New(s Store) *Service {
	return &Service{store: s}
}

// Decide implements the authoritative check (spec section 3). It assumes
// the caller (internal/httpserver) has already established that this is
// a trusted, mTLS-authenticated Traefik call and that req's fields were
// parsed from well-formed metadata -- malformed metadata is a 400 that
// never reaches here, and "trusted caller" is a transport-level fact this
// package doesn't re-verify.
//
// A non-nil error means the decision could not be made at all (database
// unavailable, decision timeout) -- the caller must fail closed (503),
// never fall back to allow.
func (s *Service) Decide(ctx context.Context, req AuthRequest) (Decision, error) {
	if req.CookieValue == "" {
		return Decision{Category: CategoryMissingOrInvalidCredential, Reason: "cookie_missing"}, nil
	}

	tokenHash := sha256.Sum256([]byte(req.CookieValue))

	snap, err := s.store.GetAccessSnapshot(ctx, req.Host, tokenHash[:])
	if err != nil {
		return Decision{}, fmt.Errorf("authz: access snapshot: %w", err)
	}
	if snap == nil {
		return Decision{Category: CategoryUnknownHost, Reason: "unknown_host"}, nil
	}
	if !snap.ApplicationEnabled {
		return Decision{Category: CategoryRevokedOrDisabled, Reason: "application_disabled"}, nil
	}
	if !snap.CredentialFound {
		return Decision{Category: CategoryMissingOrInvalidCredential, Reason: "credential_not_found"}, nil
	}
	if snap.CredentialApplicationID != snap.ApplicationID {
		// The presented credential is valid for a different application
		// than this hostname's -- treat identically to "not found" (spec
		// section 4: a copied cookie must fail even if a client bypasses
		// normal browser cookie scope).
		return Decision{Category: CategoryMissingOrInvalidCredential, Reason: "cross_application_credential"}, nil
	}
	if snap.CredentialRevoked {
		return Decision{Category: CategoryRevokedOrDisabled, Reason: "credential_revoked"}, nil
	}
	if snap.AuthorizationRevoked {
		return Decision{Category: CategoryRevokedOrDisabled, Reason: "authorization_revoked"}, nil
	}
	if !snap.AuthorizationActivated {
		return Decision{Category: CategoryMissingOrInvalidCredential, Reason: "unclaimed"}, nil
	}
	if !snap.DatabaseNow.Before(snap.AuthorizationExpiresAt) {
		return Decision{Category: CategoryMissingOrInvalidCredential, Reason: "authorization_expired"}, nil
	}
	if !snap.DatabaseNow.Before(snap.CredentialAbsoluteExpiresAt) {
		return Decision{Category: CategoryMissingOrInvalidCredential, Reason: "credential_expired"}, nil
	}

	// Every check above passed -- this request would otherwise be
	// Allow. Before committing to that, check whether the IP/User-Agent
	// changed since this authorization's last successful access
	// (compared against snap's last-seen values, captured BEFORE
	// TouchLastSeen below overwrites them) and, if so, apply whichever
	// revocation-policy action is configured for that signal. Unlike
	// TouchLastSeen, a "revoke" outcome here is structural, not
	// advisory: it changes the Allow/Deny answer this same request
	// receives, so it must happen synchronously in this same call, not
	// as a best-effort side effect.
	action, signal := s.resolveChangeSignal(snap, req)
	switch action {
	case revokepolicy.ActionRevoke:
		reason := string(signal)
		if err := s.store.RevokeAuthorization(ctx, snap.AuthorizationID, snap.AuthorizationVersion, reason, revokePolicyActor); err != nil {
			if errors.Is(err, store.ErrConflict) {
				// Something else (an admin's own renew/revoke) already
				// changed this authorization concurrently -- deny
				// rather than silently falling through to Allow; a
				// concurrent change means this decision's own premise
				// no longer holds, and denying is the safe default.
				return Decision{Category: CategoryRevokedOrDisabled, Reason: reason}, nil
			}
			return Decision{}, fmt.Errorf("authz: revoking for policy %s: %w", signal, err)
		}
		return Decision{Category: CategoryRevokedOrDisabled, Reason: reason}, nil
	case revokepolicy.ActionFlagForReview:
		if err := s.store.FlagAuthorizationForReview(ctx, snap.AuthorizationID, snap.ApplicationID, string(signal)); err != nil {
			log.Printf("authz: flagging authorization %s for review failed (non-fatal): %v", snap.AuthorizationID, err)
		}
	case revokepolicy.ActionWarn:
		if err := s.store.RecordRevocationPolicyWarning(ctx, snap.AuthorizationID, snap.ApplicationID, string(signal)); err != nil {
			log.Printf("authz: recording policy warning for authorization %s failed (non-fatal): %v", snap.AuthorizationID, err)
		}
	}

	// Allow. Last-seen is advisory (spec section 8): its failure must not
	// affect the decision already made.
	if err := s.store.TouchLastSeen(ctx, snap.AuthorizationID, req.ClientAddr, req.UserAgent); err != nil {
		log.Printf("authz: touch last seen for authorization %s failed (non-fatal): %v", snap.AuthorizationID, err)
	}

	return Decision{Category: CategoryAllow, Reason: "allow"}, nil
}

// resolveChangeSignal compares req's IP/User-Agent against snap's own
// last-seen values and resolves the more severe of whichever signals
// actually fired, per the layered session -> application -> global
// override (internal/revokepolicy.Resolve). A nil LastSeen field means
// this credential has never been successfully used before -- that
// first-use baseline must never itself fire a signal, so no comparison
// is made until there's something to compare against. IP comparison
// parses both sides as net.IP and compares via Equal, not string
// equality, so differing-but-equivalent textual forms of the same
// address (e.g. IPv6 zero-compression) can never cause a false
// positive.
func (s *Service) resolveChangeSignal(snap *store.AccessSnapshot, req AuthRequest) (revokepolicy.Action, revokepolicy.Signal) {
	best := revokepolicy.ActionOff
	var bestSignal revokepolicy.Signal

	if snap.LastSeenIP != nil && req.ClientAddr != "" {
		if current := net.ParseIP(req.ClientAddr); current != nil && !current.Equal(*snap.LastSeenIP) {
			action := revokepolicy.Resolve(snap.RevokePolicyIPChangedSession, snap.RevokePolicyIPChangedApp, revokepolicy.Action(snap.RevokePolicyIPChangedGlobal))
			if action.MoreSevere(best) {
				best, bestSignal = action, revokepolicy.SignalIPChanged
			}
		}
	}
	if snap.LastSeenUserAgent != nil && req.UserAgent != "" && *snap.LastSeenUserAgent != req.UserAgent {
		action := revokepolicy.Resolve(snap.RevokePolicyUserAgentChangedSession, snap.RevokePolicyUserAgentChangedApp, revokepolicy.Action(snap.RevokePolicyUserAgentChangedGlobal))
		if action.MoreSevere(best) {
			best, bestSignal = action, revokepolicy.SignalUserAgentChanged
		}
	}
	return best, bestSignal
}
