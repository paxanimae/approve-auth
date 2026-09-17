package enrollment

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/traefik-manual-proxy/internal/store"
)

// Config is the subset of internal/config.Config this package needs.
// cmd/server constructs it from the real config; keeping it narrow here
// means this package's tests don't need to know about unrelated
// settings (OIDC, admin listener addresses, ...).
type Config struct {
	RequestTTL                     time.Duration
	ClaimTTL                       time.Duration
	ClaimRetryTTL                  time.Duration
	CredentialMaxAge               time.Duration
	ClaimEncryptionKey             []byte
	ClaimEncryptionKeyID           string
	PendingRequestsPerHourPerAppIP int
}

// Store is the persistence surface this package needs. Defined here
// (not just *store.DB) so tests can substitute a fake for the pure
// business-rule branches, the same pattern as internal/authz.Store.
type Store interface {
	GetApplicationByHostname(ctx context.Context, hostname string) (store.Application, bool, error)

	CreateEnrollmentContext(ctx context.Context, applicationID uuid.UUID, pendingTokenHash, csrfSecret []byte, expiresAt time.Time) (store.EnrollmentContext, error)
	GetLiveEnrollmentContextByTokenHash(ctx context.Context, hash []byte) (store.EnrollmentContext, bool, error)
	ConsumeEnrollmentContext(ctx context.Context, id uuid.UUID) error

	CreateApprovalRequest(ctx context.Context, p store.CreateApprovalRequestParams) (store.ApprovalRequest, error)
	GetApprovalRequestByTokenHash(ctx context.Context, hash []byte) (store.ApprovalRequest, bool, error)
	CancelApprovalRequest(ctx context.Context, requestID uuid.UUID) error

	ClaimApproved(ctx context.Context, requestID uuid.UUID, tokenHash []byte, credentialMaxAge time.Duration) (credentialID, applicationID uuid.UUID, alreadyClaimed bool, err error)
	SaveClaimEnvelope(ctx context.Context, requestID, credentialID uuid.UUID, encryptionKeyID string, nonce, ciphertext []byte, expiresAt time.Time) error
	GetLiveClaimEnvelope(ctx context.Context, requestID uuid.UUID) (store.ClaimResult, bool, error)
	DeleteClaimEnvelope(ctx context.Context, requestID uuid.UUID) error

	IncrementRateLimit(ctx context.Context, bucketKey string, windowStart time.Time, windowTTL time.Duration) (int, error)

	RevokeByCredentialHash(ctx context.Context, hostname string, tokenHash []byte, revokedBy string) error
}

// BootstrapInput/Result back GET /__manual-approval/request (spec
// section 5, step 2).
type BootstrapInput struct {
	Hostname             string
	ExistingPendingToken string // "" if the browser has no pending cookie yet
}

type BootstrapResult struct {
	ApplicationDisplayName string
	ApplicationHostname    string
	// RawPendingToken is only set when a new context was created --
	// empty means the caller should keep the browser's existing cookie
	// as-is (an existing valid context was reused).
	RawPendingToken string
	CSRFToken       string
}

// SubmitRequestInput/Result back POST /__manual-approval/requests (spec
// section 5, step 3).
type SubmitRequestInput struct {
	PendingTokenRaw string
	CSRFToken       string
	Label           string
	Message         string
	ReturnTo        string
	ClientIP        string
	UserAgent       string
}

type SubmitRequestResult struct {
	RequestID        string
	VerificationCode string
}

// StatusResult backs GET /__manual-approval/status (spec section 5,
// step 4/5) -- deliberately no PII beyond the caller's own request.
type StatusResult struct {
	State            string
	VerificationCode string
	PublicMessage    string
	RequestedAt      time.Time
	DeadlineAt       time.Time
	ClaimDeadlineAt  *time.Time
	ServerTime       time.Time
	// CSRFToken is set only while the enrollment context backing this
	// pending proof is still live -- it's what the waiting page needs to
	// render a working cancel/claim form. Empty means those actions are
	// no longer available (spec section 5: the browser must request
	// access again).
	CSRFToken string
}

// ClaimOutcome backs POST /__manual-approval/claim.
type ClaimOutcome struct {
	RawAccessToken string
	ReturnTo       string
}
