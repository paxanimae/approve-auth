package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/frid-iks/approve-auth/internal/metrics"
	"github.com/frid-iks/approve-auth/internal/store"
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

// ErrNotFound means the request/authorization a note was aimed at
// doesn't exist -- distinct from ErrConflict, which specifically means
// a version/state mismatch on a row that does exist.
var ErrNotFound = errors.New("admin: no such record")

// ErrInvalidNote means a note's body was empty or exceeded migration
// 000013's request_notes_body_length/authorization_notes_body_length
// bound (2000 characters) -- checked here too so the caller gets a
// clean 422 instead of a raw constraint-violation error.
var ErrInvalidNote = errors.New("admin: note body must be between 1 and 2000 characters")

// ErrInvalidRevocationThreshold means UpdateGlobalSettings received a
// non-positive RevocationInactivityThreshold. Unlike an application's
// own revocation-policy override, global_settings' inactivity
// threshold (migration 000019) is a NOT NULL column with no "unset"
// state, so it must always be a real, positive duration.
var ErrInvalidRevocationThreshold = errors.New("admin: revocation_inactivity_threshold must be positive")

type Service struct {
	store Store
	cfg   Config
}

func New(s Store, cfg Config) *Service {
	return &Service{store: s, cfg: cfg}
}

// recordAdminAction is spec section 15's "approval/denial/renewal/
// revocation totals" -- outcome is one of success/conflict/error, never
// anything with unbounded cardinality.
func recordAdminAction(action string, err error) {
	outcome := "success"
	switch {
	case err == nil:
	case errors.Is(err, ErrConflict), errors.Is(err, ErrInvalidExpiry), errors.Is(err, ErrDuplicateHostname), errors.Is(err, ErrInvalidDuration):
		outcome = "rejected"
	default:
		outcome = "error"
	}
	metrics.AdminActions.WithLabelValues(action, outcome).Inc()
}

// Approve implements spec section 5 step 6 / section 7: approval sets
// accepted state but the browser must still claim its credential.
func (s *Service) Approve(ctx context.Context, in ApproveInput) (result ApproveResult, err error) {
	defer func() { recordAdminAction("approve", err) }()

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

	auth, err := s.store.ApproveRequest(ctx, requestID, in.ExpectedVersion, expiresAt, s.cfg.ClaimTTL, in.Label, in.PrivateNote, in.ApprovedBy,
		in.RevokePolicyIPChanged, in.RevokePolicyUserAgentChanged, in.RevokePolicyInactivityExceeded)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return ApproveResult{}, ErrConflict
		}
		return ApproveResult{}, fmt.Errorf("admin: approve: %w", err)
	}
	return ApproveResult{AuthorizationID: auth.ID.String(), ExpiresAt: auth.ExpiresAt}, nil
}

func (s *Service) Deny(ctx context.Context, in DenyInput) (err error) {
	defer func() { recordAdminAction("deny", err) }()

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

func (s *Service) Revoke(ctx context.Context, in RevokeInput) (err error) {
	defer func() { recordAdminAction("revoke", err) }()

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
func (s *Service) Renew(ctx context.Context, in RenewInput) (err error) {
	defer func() { recordAdminAction("renew", err) }()

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

// ClearAuthorizationFlag acknowledges a revocation-policy
// "flag_for_review" state (internal/revokepolicy) once reviewed --
// idempotent, clearing an authorization that isn't flagged is a no-op,
// not an error.
func (s *Service) ClearAuthorizationFlag(ctx context.Context, in ClearAuthorizationFlagInput) (err error) {
	defer func() { recordAdminAction("clear_authorization_flag", err) }()

	authorizationID, err := uuid.Parse(in.AuthorizationID)
	if err != nil {
		return fmt.Errorf("admin: clear authorization flag: invalid authorization id: %w", err)
	}
	if err := s.store.ClearAuthorizationFlag(ctx, authorizationID, in.ClearedBy); err != nil {
		return fmt.Errorf("admin: clear authorization flag: %w", err)
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

	app, err := s.store.CreateApplication(ctx, in.Hostname, in.DisplayName, in.Description, defaultDuration, maxDuration, in.ContactInfo, in.NotifyEmail, in.NotifyWebhookURL)
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
		ContactInfo: in.ContactInfo, NotifyEmail: in.NotifyEmail, NotifyWebhookURL: in.NotifyWebhookURL,
		RevokePolicyIPChanged: in.RevokePolicyIPChanged, RevokePolicyUserAgentChanged: in.RevokePolicyUserAgentChanged,
		RevokePolicyInactivityExceeded: in.RevokePolicyInactivityExceeded,
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

// AddRequestNote implements POST /api/v1/requests/{id}/notes. Notes are
// append-only (spec-adjacent to the audit trail's own immutability --
// see migration 000013): there is deliberately no edit or delete.
func (s *Service) AddRequestNote(ctx context.Context, in AddRequestNoteInput) (store.RequestNote, error) {
	requestID, err := uuid.Parse(in.RequestID)
	if err != nil {
		return store.RequestNote{}, fmt.Errorf("admin: add request note: invalid request id: %w", err)
	}
	body := strings.TrimSpace(in.Body)
	if body == "" || len(body) > 2000 {
		return store.RequestNote{}, ErrInvalidNote
	}

	note, err := s.store.CreateRequestNote(ctx, requestID, in.AuthorBy, body)
	if err != nil {
		switch pgConstraintName(err) {
		case "request_notes_request_id_fkey":
			return store.RequestNote{}, ErrNotFound
		case "request_notes_body_length":
			return store.RequestNote{}, ErrInvalidNote
		}
		return store.RequestNote{}, fmt.Errorf("admin: add request note: %w", err)
	}
	return note, nil
}

// AddAuthorizationNote is AddRequestNote's exact counterpart for an
// authorization (session) instead of a request.
func (s *Service) AddAuthorizationNote(ctx context.Context, in AddAuthorizationNoteInput) (store.AuthorizationNote, error) {
	authorizationID, err := uuid.Parse(in.AuthorizationID)
	if err != nil {
		return store.AuthorizationNote{}, fmt.Errorf("admin: add authorization note: invalid authorization id: %w", err)
	}
	body := strings.TrimSpace(in.Body)
	if body == "" || len(body) > 2000 {
		return store.AuthorizationNote{}, ErrInvalidNote
	}

	note, err := s.store.CreateAuthorizationNote(ctx, authorizationID, in.AuthorBy, body)
	if err != nil {
		switch pgConstraintName(err) {
		case "authorization_notes_authorization_id_fkey":
			return store.AuthorizationNote{}, ErrNotFound
		case "authorization_notes_body_length":
			return store.AuthorizationNote{}, ErrInvalidNote
		}
		return store.AuthorizationNote{}, fmt.Errorf("admin: add authorization note: %w", err)
	}
	return note, nil
}

// GrantApplicationOwner implements POST /api/v1/applications/{id}/owners.
// in.Subject non-empty is validated by the caller (httpserver), matching
// how other simple required-field checks in this API are handled at the
// HTTP layer rather than as a Service-level error.
func (s *Service) GrantApplicationOwner(ctx context.Context, in GrantApplicationOwnerInput) error {
	applicationID, err := uuid.Parse(in.ApplicationID)
	if err != nil {
		return fmt.Errorf("admin: grant application owner: invalid application id: %w", err)
	}
	if err := s.store.GrantApplicationOwner(ctx, applicationID, in.Subject, in.GrantedBy); err != nil {
		if pgConstraintName(err) == "application_owners_application_id_fkey" {
			return ErrNotFound
		}
		return fmt.Errorf("admin: grant application owner: %w", err)
	}
	return nil
}

// RevokeApplicationOwner implements DELETE
// /api/v1/applications/{id}/owners/{subject}.
func (s *Service) RevokeApplicationOwner(ctx context.Context, in RevokeApplicationOwnerInput) error {
	applicationID, err := uuid.Parse(in.ApplicationID)
	if err != nil {
		return fmt.Errorf("admin: revoke application owner: invalid application id: %w", err)
	}
	if err := s.store.RevokeApplicationOwner(ctx, applicationID, in.Subject, in.RevokedBy); err != nil {
		return fmt.Errorf("admin: revoke application owner: %w", err)
	}
	return nil
}

// UpdateGlobalSettings implements PATCH /api/v1/settings -- the
// deployment-wide business-rule defaults moved off static config into
// migration 000019's global_settings table, so an administrator's
// edit here takes effect on the very next request/decision/delivery
// with no restart, unlike everything still in internal/config.
func (s *Service) UpdateGlobalSettings(ctx context.Context, in UpdateGlobalSettingsInput) (store.GlobalSettings, error) {
	if in.RevocationInactivityThreshold != nil && *in.RevocationInactivityThreshold <= 0 {
		return store.GlobalSettings{}, ErrInvalidRevocationThreshold
	}

	settings, err := s.store.UpdateGlobalSettings(ctx, in.ExpectedVersion, store.UpdateGlobalSettingsParams{
		ContactInfo: in.ContactInfo, NotifyEmailFrom: in.NotifyEmailFrom, NotifyDefaultEmail: in.NotifyDefaultEmail, NotifyDefaultWebhookURL: in.NotifyDefaultWebhookURL,
		RevokePolicyIPChanged: in.RevokePolicyIPChanged, RevokePolicyUserAgentChanged: in.RevokePolicyUserAgentChanged,
		RevokePolicyInactivityExceeded: in.RevokePolicyInactivityExceeded, RevocationInactivityThreshold: in.RevocationInactivityThreshold,
	}, in.UpdatedBy)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.GlobalSettings{}, ErrConflict
		}
		return store.GlobalSettings{}, fmt.Errorf("admin: update global settings: %w", err)
	}
	return settings, nil
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
