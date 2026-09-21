package enrollment

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/store"
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
	BootstrapPerMinutePerIP        int
	StatusPerMinutePerPendingProof int
	// DefaultContactInfo is shown on the request page for any
	// application that has no contact_info override of its own.
	DefaultContactInfo string
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

// BootstrapInput/Result back GET /__approve-auth/request (spec
// section 5, step 2).
type BootstrapInput struct {
	Hostname             string
	ExistingPendingToken string // "" if the browser has no pending cookie yet
	ClientIP             string
}

type BootstrapResult struct {
	ApplicationDisplayName string
	ApplicationHostname    string
	// ContactInfo is the application's own override if it has one,
	// otherwise Config.DefaultContactInfo -- resolved here so the
	// template never needs to know the fallback rule itself.
	ContactInfo string
	// RawPendingToken is only set when a new context was created --
	// empty means the caller should keep the browser's existing cookie
	// as-is (an existing valid context was reused).
	RawPendingToken string
	CSRFToken       string
}

// SubmitRequestInput/Result back POST /__approve-auth/requests (spec
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
	RequestID        string `json:"request_id"`
	VerificationCode string `json:"verification_code"`
}

// StatusResult backs GET /__approve-auth/status (spec section 5,
// step 4/5) -- deliberately no PII beyond the caller's own request. JSON
// tags matter here specifically: the HTTP handler marshals this struct
// directly rather than building a map (spec section 9: "JSON uses
// snake_case").
type StatusResult struct {
	State            string     `json:"state"`
	VerificationCode string     `json:"verification_code"`
	PublicMessage    string     `json:"public_message"`
	RequestedAt      time.Time  `json:"requested_at"`
	DeadlineAt       time.Time  `json:"deadline_at"`
	ClaimDeadlineAt  *time.Time `json:"claim_deadline_at,omitempty"`
	ServerTime       time.Time  `json:"server_time"`
	// CSRFToken is set only while the enrollment context backing this
	// pending proof is still live -- it's what the waiting page needs to
	// render a working cancel/claim form. Empty means those actions are
	// no longer available (spec section 5: the browser must request
	// access again).
	CSRFToken string `json:"csrf_token,omitempty"`
}

// ClaimOutcome backs POST /__approve-auth/claim.
type ClaimOutcome struct {
	RawAccessToken string
	ReturnTo       string
}
