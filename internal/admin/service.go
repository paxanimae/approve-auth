package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/traefik-manual-proxy/internal/store"
)

// ErrConflict means the request/authorization wasn't in the state the
// caller expected (stale version, already decided/revoked) -- callers
// map this to 409 (spec section 9).
var ErrConflict = errors.New("admin: conflict (stale version or unexpected state)")

// ErrInvalidExpiry means the chosen expiry violates spec section 7's
// bounds: it must be in the future and within the application's
// configured maximum authorization duration.
var ErrInvalidExpiry = errors.New("admin: expires_at must be in the future and within the configured maximum duration")

type Service struct {
	store Store
	cfg   Config
}

func New(s Store, cfg Config) *Service {
	return &Service{store: s, cfg: cfg}
}

// Approve implements spec section 5 step 6 / section 7: approval sets
// accepted state but the browser must still claim its credential.
func (s *Service) Approve(ctx context.Context, in ApproveInput) (ApproveResult, error) {
	requestID, err := uuid.Parse(in.RequestID)
	if err != nil {
		return ApproveResult{}, fmt.Errorf("admin: approve: invalid request id: %w", err)
	}

	expiresAt := in.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(s.cfg.DefaultAuthorizationDuration)
	}
	now := time.Now()
	if !expiresAt.After(now) || expiresAt.After(now.Add(s.cfg.MaxAuthorizationDuration)) {
		return ApproveResult{}, ErrInvalidExpiry
	}

	auth, err := s.store.ApproveRequest(ctx, requestID, in.ExpectedVersion, expiresAt, s.cfg.ClaimTTL, in.Label, in.PrivateNote, in.ApprovedBy)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return ApproveResult{}, ErrConflict
		}
		return ApproveResult{}, fmt.Errorf("admin: approve: %w", err)
	}
	return ApproveResult{AuthorizationID: auth.ID.String(), ExpiresAt: auth.ExpiresAt}, nil
}

func (s *Service) Deny(ctx context.Context, in DenyInput) error {
	requestID, err := uuid.Parse(in.RequestID)
	if err != nil {
		return fmt.Errorf("admin: deny: invalid request id: %w", err)
	}
	if err := s.store.DenyRequest(ctx, requestID, in.ExpectedVersion, in.Reason, in.PublicMessage, in.DeniedBy); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return ErrConflict
		}
		return fmt.Errorf("admin: deny: %w", err)
	}
	return nil
}

func (s *Service) Revoke(ctx context.Context, in RevokeInput) error {
	authorizationID, err := uuid.Parse(in.AuthorizationID)
	if err != nil {
		return fmt.Errorf("admin: revoke: invalid authorization id: %w", err)
	}
	if err := s.store.RevokeAuthorization(ctx, authorizationID, in.ExpectedVersion, in.Reason, in.RevokedBy); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return ErrConflict
		}
		return fmt.Errorf("admin: revoke: %w", err)
	}
	return nil
}

// Renew implements spec section 7's renewal rules; the actual
// new_expires_at > current / > now / <= credential-ceiling checks live
// in store.RenewAuthorization since they need a locked, consistent read
// of both the authorization and its credential.
func (s *Service) Renew(ctx context.Context, in RenewInput) error {
	authorizationID, err := uuid.Parse(in.AuthorizationID)
	if err != nil {
		return fmt.Errorf("admin: renew: invalid authorization id: %w", err)
	}
	if err := s.store.RenewAuthorization(ctx, authorizationID, in.ExpectedVersion, in.NewExpiresAt, in.RenewedBy); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return ErrConflict
		}
		return fmt.Errorf("admin: renew: %w", err)
	}
	return nil
}
