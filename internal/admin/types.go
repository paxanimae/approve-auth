package admin

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/store"
)

// Config is the subset of internal/config.Config this package needs
// (spec section 7): the bounds Approve and Renew must enforce.
type Config struct {
	DefaultAuthorizationDuration time.Duration
	MaxAuthorizationDuration     time.Duration
	ClaimTTL                     time.Duration
}

// Store is the persistence surface this package needs.
type Store interface {
	ApproveRequest(ctx context.Context, requestID uuid.UUID, expectedVersion int32, expiresAt time.Time, claimTTL time.Duration, label, privateNote, approvedBy string, revokePolicyIPChanged, revokePolicyUserAgentChanged, revokePolicyInactivityExceeded *string) (store.Authorization, error)
	DenyRequest(ctx context.Context, requestID uuid.UUID, expectedVersion int32, reason, publicMessage, deniedBy string) error
	RevokeAuthorization(ctx context.Context, authorizationID uuid.UUID, expectedVersion int32, reason, revokedBy string) error
	RenewAuthorization(ctx context.Context, authorizationID uuid.UUID, expectedVersion int32, newExpiresAt time.Time, renewedBy string) error
	GetAuthorizationByID(ctx context.Context, id uuid.UUID) (store.Authorization, bool, error)
	ClearAuthorizationFlag(ctx context.Context, authorizationID uuid.UUID, clearedBy string) error

	CreateApplication(ctx context.Context, hostname, displayName, description string, defaultDuration, maxDuration time.Duration, contactInfo, notifyEmail, notifyWebhookURL string) (store.Application, error)
	GetApplicationByID(ctx context.Context, id uuid.UUID) (store.Application, bool, error)
	UpdateApplication(ctx context.Context, id uuid.UUID, expectedVersion int32, p store.UpdateApplicationParams, updatedBy string) (store.Application, error)
	DisableApplication(ctx context.Context, id uuid.UUID, expectedVersion int32, reason, disabledBy string) (store.Application, int, int, error)
	EnableApplication(ctx context.Context, id uuid.UUID, expectedVersion int32, enabledBy string) (store.Application, error)

	CreateRequestNote(ctx context.Context, requestID uuid.UUID, authorSubject, body string) (store.RequestNote, error)
	CreateAuthorizationNote(ctx context.Context, authorizationID uuid.UUID, authorSubject, body string) (store.AuthorizationNote, error)

	GrantApplicationOwner(ctx context.Context, applicationID uuid.UUID, subject, grantedBy string) error
	RevokeApplicationOwner(ctx context.Context, applicationID uuid.UUID, subject, revokedBy string) error
	ListApplicationOwners(ctx context.Context, applicationID uuid.UUID) ([]string, error)
}

// ApproveInput backs POST /api/v1/requests/{id}/approve (spec section 9).
type ApproveInput struct {
	RequestID       string
	ExpectedVersion int32
	// ExpiresAt: zero means "use the application's default duration"
	// (spec section 7: "default now + 30 days").
	ExpiresAt   time.Time
	Label       string
	PrivateNote string
	ApprovedBy  string
	// RevokePolicy{IPChanged,UserAgentChanged,InactivityExceeded}: this
	// session's own revocation-policy overrides (internal/revokepolicy),
	// nil meaning "inherit the application's own override, or the
	// deployment-wide default". Set only here, at approval time -- v1
	// scope deliberately has no separate endpoint to edit them
	// afterward (see store.Authorization's own comment).
	RevokePolicyIPChanged          *string
	RevokePolicyUserAgentChanged   *string
	RevokePolicyInactivityExceeded *string
}

type ApproveResult struct {
	AuthorizationID string
	ExpiresAt       time.Time
}

type DenyInput struct {
	RequestID       string
	ExpectedVersion int32
	Reason          string
	PublicMessage   string
	DeniedBy        string
}

type RevokeInput struct {
	AuthorizationID string
	ExpectedVersion int32
	Reason          string
	RevokedBy       string
}

type RenewInput struct {
	AuthorizationID string
	ExpectedVersion int32
	NewExpiresAt    time.Time
	RenewedBy       string
}

// ClearAuthorizationFlagInput backs POST
// /api/v1/authorizations/{id}/clear-flag.
type ClearAuthorizationFlagInput struct {
	AuthorizationID string
	ClearedBy       string
}

// CreateApplicationInput backs POST /api/v1/applications (spec section
// 9). DefaultDuration/MaxDuration of zero mean "use the service-wide
// configured default" (Config.DefaultAuthorizationDuration /
// MaxAuthorizationDuration), the same fallback Approve uses.
type CreateApplicationInput struct {
	Hostname         string
	DisplayName      string
	Description      string
	DefaultDuration  time.Duration
	MaxDuration      time.Duration
	ContactInfo      string
	NotifyEmail      string
	NotifyWebhookURL string
}

// UpdateApplicationInput backs PATCH /api/v1/applications/{id}.
type UpdateApplicationInput struct {
	ApplicationID    string
	ExpectedVersion  int32
	DisplayName      *string
	Description      *string
	DefaultDuration  *time.Duration
	MaxDuration      *time.Duration
	ContactInfo      *string
	NotifyEmail      *string
	NotifyWebhookURL *string
	// RevokePolicy{IPChanged,UserAgentChanged,InactivityExceeded}: nil
	// means leave unchanged; a non-nil pointer sets it (an empty
	// string clears the override back to the deployment-wide
	// default), same convention as ContactInfo above.
	RevokePolicyIPChanged          *string
	RevokePolicyUserAgentChanged   *string
	RevokePolicyInactivityExceeded *string
	UpdatedBy                      string
}

// DisableApplicationInput backs POST /api/v1/applications/{id}/disable.
type DisableApplicationInput struct {
	ApplicationID   string
	ExpectedVersion int32
	Reason          string
	DisabledBy      string
}

// DisableApplicationResult reports the affected-row counts spec section
// 10 requires the confirmation UI to show.
type DisableApplicationResult struct {
	Application           store.Application
	CanceledRequests      int
	RevokedAuthorizations int
}

// EnableApplicationInput backs POST /api/v1/applications/{id}/enable.
type EnableApplicationInput struct {
	ApplicationID   string
	ExpectedVersion int32
	EnabledBy       string
}

// AddRequestNoteInput backs POST /api/v1/requests/{id}/notes.
type AddRequestNoteInput struct {
	RequestID string
	Body      string
	AuthorBy  string
}

// AddAuthorizationNoteInput backs POST /api/v1/authorizations/{id}/notes.
type AddAuthorizationNoteInput struct {
	AuthorizationID string
	Body            string
	AuthorBy        string
}

// GrantApplicationOwnerInput backs POST /api/v1/applications/{id}/owners.
// Administrator-only -- an ApplicationOwner cannot grant ownership to
// anyone, including themselves (spec: "cannot control anything else").
type GrantApplicationOwnerInput struct {
	ApplicationID string
	Subject       string
	GrantedBy     string
}

// RevokeApplicationOwnerInput backs DELETE
// /api/v1/applications/{id}/owners/{subject}.
type RevokeApplicationOwnerInput struct {
	ApplicationID string
	Subject       string
	RevokedBy     string
}
