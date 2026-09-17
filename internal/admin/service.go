package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

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

// ErrDuplicateHostname means CreateApplication collided with an already-
// registered hostname (spec section 3: "one registered, exact hostname"
// -- applications.hostname is unique).
var ErrDuplicateHostname = errors.New("admin: an application with this hostname is already registered")

// ErrInvalidDuration means a default/max duration pair violates spec
// section 8's applications_duration_positive/applications_duration_order
// constraints: both must be positive and default must not exceed max.
var ErrInvalidDuration = errors.New("admin: default_duration and max_duration must be positive, with default_duration <= max_duration")

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

// CreateApplication implements spec section 9's POST /applications.
func (s *Service) CreateApplication(ctx context.Context, in CreateApplicationInput) (store.Application, error) {
	defaultDuration := in.DefaultDuration
	if defaultDuration <= 0 {
		defaultDuration = s.cfg.DefaultAuthorizationDuration
	}
	maxDuration := in.MaxDuration
	if maxDuration <= 0 {
		maxDuration = s.cfg.MaxAuthorizationDuration
	}
	if defaultDuration <= 0 || maxDuration <= 0 || defaultDuration > maxDuration {
		return store.Application{}, ErrInvalidDuration
	}

	app, err := s.store.CreateApplication(ctx, in.Hostname, in.DisplayName, in.Description, defaultDuration, maxDuration)
	if err != nil {
		if pgConstraintName(err) == "applications_hostname_key" {
			return store.Application{}, ErrDuplicateHostname
		}
		return store.Application{}, fmt.Errorf("admin: create application: %w", err)
	}
	return app, nil
}

// UpdateApplication implements spec section 9's PATCH /applications/{id}.
func (s *Service) UpdateApplication(ctx context.Context, in UpdateApplicationInput) (store.Application, error) {
	applicationID, err := uuid.Parse(in.ApplicationID)
	if err != nil {
		return store.Application{}, fmt.Errorf("admin: update application: invalid id: %w", err)
	}
	if in.DefaultDuration != nil && *in.DefaultDuration <= 0 {
		return store.Application{}, ErrInvalidDuration
	}
	if in.MaxDuration != nil && *in.MaxDuration <= 0 {
		return store.Application{}, ErrInvalidDuration
	}

	app, err := s.store.UpdateApplication(ctx, applicationID, in.ExpectedVersion, store.UpdateApplicationParams{
		DisplayName: in.DisplayName, Description: in.Description, DefaultDuration: in.DefaultDuration, MaxDuration: in.MaxDuration,
	}, in.UpdatedBy)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.Application{}, ErrConflict
		}
		// The migration's CHECK constraints (applications_duration_positive,
		// applications_duration_order) are the authoritative guard against a
		// partial update leaving default_duration > max_duration -- caught
		// here rather than re-derived from a second read, since
		// UpdateApplication already merged the caller's changes with the
		// current row under its own row lock.
		switch pgConstraintName(err) {
		case "applications_duration_positive", "applications_duration_order":
			return store.Application{}, ErrInvalidDuration
		}
		return store.Application{}, fmt.Errorf("admin: update application: %w", err)
	}
	return app, nil
}

// DisableApplication implements spec section 9's POST
// /applications/{id}/disable.
func (s *Service) DisableApplication(ctx context.Context, in DisableApplicationInput) (DisableApplicationResult, error) {
	applicationID, err := uuid.Parse(in.ApplicationID)
	if err != nil {
		return DisableApplicationResult{}, fmt.Errorf("admin: disable application: invalid id: %w", err)
	}
	app, canceled, revoked, err := s.store.DisableApplication(ctx, applicationID, in.ExpectedVersion, in.Reason, in.DisabledBy)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return DisableApplicationResult{}, ErrConflict
		}
		return DisableApplicationResult{}, fmt.Errorf("admin: disable application: %w", err)
	}
	return DisableApplicationResult{Application: app, CanceledRequests: canceled, RevokedAuthorizations: revoked}, nil
}

// EnableApplication implements spec section 9's POST
// /applications/{id}/enable.
func (s *Service) EnableApplication(ctx context.Context, in EnableApplicationInput) (store.Application, error) {
	applicationID, err := uuid.Parse(in.ApplicationID)
	if err != nil {
		return store.Application{}, fmt.Errorf("admin: enable application: invalid id: %w", err)
	}
	app, err := s.store.EnableApplication(ctx, applicationID, in.ExpectedVersion, in.EnabledBy)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.Application{}, ErrConflict
		}
		return store.Application{}, fmt.Errorf("admin: enable application: %w", err)
	}
	return app, nil
}

// pgConstraintName mirrors internal/enrollment's own helper of the same
// name -- small enough, and this package has no other reason to depend
// on internal/enrollment, that duplicating it beats sharing it.
func pgConstraintName(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}
