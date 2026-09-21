package store

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// The types below are plain structs mirroring each migration's columns --
// typed building blocks for the repository methods a later milestone adds
// alongside the code that actually calls them. They carry no behavior.

type Application struct {
	ID                     uuid.UUID
	Hostname               string
	DisplayName            string
	Description            string
	Enabled                bool
	DefaultDurationSeconds int32
	MaxDurationSeconds     int32
	CreatedAt              time.Time
	UpdatedAt              time.Time
	ArchivedAt             *time.Time
	Version                int32
}

type EnrollmentContext struct {
	ID               uuid.UUID
	ApplicationID    uuid.UUID
	PendingTokenHash []byte
	CSRFSecret       []byte
	CreatedAt        time.Time
	ExpiresAt        time.Time
	ConsumedAt       *time.Time
}

type ApprovalRequest struct {
	ID                    uuid.UUID
	ApplicationID         uuid.UUID
	PendingTokenHash      []byte
	VerificationCode      string
	Label                 *string
	Message               *string
	ReturnPath            *string
	Status                string
	RequestedAt           time.Time
	DeadlineAt            time.Time
	DecidedAt             *time.Time
	DecidedBy             *string
	ClaimDeadlineAt       *time.Time
	ClaimedAt             *time.Time
	PublicDecisionMessage *string
	PrivateNote           *string
	SourceIP              *net.IP
	UserAgent             *string
	Version               int32

	// ApplicationHostname/ApplicationDisplayName are only populated by
	// the admin-facing reads (GetApprovalRequestByID, ListApprovalRequests)
	// via a join against applications -- left "" from CreateApprovalRequest
	// and GetApprovalRequestByTokenHash, which don't need them and, for
	// the INSERT...RETURNING case, structurally can't join another table.
	ApplicationHostname    string
	ApplicationDisplayName string
}

type Authorization struct {
	ID                uuid.UUID
	ApplicationID     uuid.UUID
	RequestID         uuid.UUID
	Label             *string
	ApprovedBy        string
	ApprovedAt        time.Time
	ActivatedAt       *time.Time
	ExpiresAt         time.Time
	RevokedAt         *time.Time
	RevokedBy         *string
	RevocationReason  *string
	LastSeenAt        *time.Time
	LastSeenIP        *net.IP
	LastSeenUserAgent *string
	Version           int32

	// ApplicationHostname/ApplicationDisplayName come from a join against
	// applications -- see GetAuthorizationByID/ListAuthorizations, the
	// only two callers of authorizationColumns/scanAuthorization.
	ApplicationHostname    string
	ApplicationDisplayName string
}

type Credential struct {
	ID                uuid.UUID
	AuthorizationID   uuid.UUID
	ApplicationID     uuid.UUID
	TokenHash         []byte
	IssuedAt          time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
}

type ClaimResult struct {
	RequestID       uuid.UUID
	CredentialID    uuid.UUID
	EncryptionKeyID string
	Nonce           []byte
	Ciphertext      []byte
	ExpiresAt       time.Time
}

type AdminSession struct {
	ID                uuid.UUID
	TokenHash         []byte
	OIDCIssuer        string
	OIDCSubject       string
	DisplayName       *string
	Role              string
	RoleSnapshotAt    time.Time
	CreatedAt         time.Time
	LastSeenAt        *time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	CSRFSecret        []byte
}

type OIDCTransaction struct {
	StateHash             []byte
	Nonce                 string
	EncryptedPKCEVerifier []byte
	SafeReturnPath        *string
	ExpiresAt             time.Time
	ConsumedAt            *time.Time
}

type AuditEvent struct {
	ID              uuid.UUID
	OccurredAt      time.Time
	ActorType       string
	ActorSubject    *string
	Action          string
	ApplicationID   *uuid.UUID
	RequestID       *uuid.UUID
	AuthorizationID *uuid.UUID
	CorrelationID   uuid.UUID
	SourceIP        *net.IP
	Reason          *string
	RedactedBefore  []byte // JSONB
	RedactedAfter   []byte // JSONB
	Outcome         string
}

type RateLimitBucket struct {
	BucketKey   string
	WindowStart time.Time
	Count       int32
	ExpiresAt   time.Time
}

type IdempotencyRecord struct {
	ID             uuid.UUID
	ActorSessionID uuid.UUID
	Key            string
	Operation      string
	RequestHash    []byte
	ResultStatus   int32
	ResultBody     []byte // JSONB
	ExpiresAt      time.Time
}
