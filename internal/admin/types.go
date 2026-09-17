package admin

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/traefik-manual-proxy/internal/store"
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
	ApproveRequest(ctx context.Context, requestID uuid.UUID, expectedVersion int32, expiresAt time.Time, claimTTL time.Duration, label, privateNote, approvedBy string) (store.Authorization, error)
	DenyRequest(ctx context.Context, requestID uuid.UUID, expectedVersion int32, reason, publicMessage, deniedBy string) error
	RevokeAuthorization(ctx context.Context, authorizationID uuid.UUID, expectedVersion int32, reason, revokedBy string) error
	RenewAuthorization(ctx context.Context, authorizationID uuid.UUID, expectedVersion int32, newExpiresAt time.Time, renewedBy string) error
	GetAuthorizationByID(ctx context.Context, id uuid.UUID) (store.Authorization, bool, error)
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
