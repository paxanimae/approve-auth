package authz

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/google/uuid"

	"github.com/frid-iks/traefik-manual-proxy/internal/store"
)

// Store is the read/write surface Decide needs. Defined here (not just
// used as *store.DB directly) so tests can substitute a fake and exercise
// every branch of the decision table without a real database.
type Store interface {
	GetAccessSnapshot(ctx context.Context, hostname string, credentialTokenHash []byte) (*store.AccessSnapshot, error)
	TouchLastSeen(ctx context.Context, authorizationID uuid.UUID, clientIP, userAgent string) error
}

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

	// Allow. Last-seen is advisory (spec section 8): its failure must not
	// affect the decision already made.
	if err := s.store.TouchLastSeen(ctx, snap.AuthorizationID, req.ClientAddr, req.UserAgent); err != nil {
		log.Printf("authz: touch last seen for authorization %s failed (non-fatal): %v", snap.AuthorizationID, err)
	}

	return Decision{Category: CategoryAllow, Reason: "allow"}, nil
}
