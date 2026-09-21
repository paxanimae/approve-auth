package adminsession

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/oidc"
	"github.com/frid-iks/approve-auth/internal/store"
)

// Config is the subset of internal/config.Config this package needs.
type Config struct {
	OIDCAdminGroups    []string
	OIDCViewerGroups   []string
	IdleTTL            time.Duration
	AbsoluteTTL        time.Duration
	TransactionTTL     time.Duration // spec section 9: 10-minute expiry
	StateEncryptionKey []byte
}

// Store is the persistence surface this package needs.
type Store interface {
	CreateOIDCTransaction(ctx context.Context, stateHash []byte, nonce string, encryptedPKCEVerifier []byte, safeReturnPath string, expiresAt time.Time) error
	ConsumeOIDCTransaction(ctx context.Context, stateHash []byte) (store.OIDCTransaction, bool, error)

	CreateAdminSession(ctx context.Context, oidcIssuer, oidcSubject, displayName, role string, tokenHash, csrfSecret []byte, absoluteExpiresAt time.Time) (store.AdminSession, error)
	GetLiveAdminSessionByTokenHash(ctx context.Context, hash []byte) (store.AdminSession, bool, error)
	TouchAdminSessionLastSeen(ctx context.Context, id uuid.UUID) error
	RevokeAdminSession(ctx context.Context, id uuid.UUID) error

	// GetOwnedApplicationIDs backs the application_owner role fallback
	// in HandleCallback -- see its own comment for why this is checked
	// here rather than snapshotted anywhere.
	GetOwnedApplicationIDs(ctx context.Context, subject string) ([]uuid.UUID, error)
}

// OIDCClient is exactly internal/oidc.Client's shape (reused directly,
// not redeclared -- Go interface satisfaction needs the method
// signatures, including internal/oidc.Identity, to match exactly).
type OIDCClient = oidc.Client

type BeginLoginResult struct {
	RedirectURL string
}

// SessionInfo is what the admin API's own auth middleware and the /me
// endpoint need.
type SessionInfo struct {
	ID          uuid.UUID
	Subject     string // OIDC subject -- stable actor identifier for audit fields, unlike DisplayName
	DisplayName string
	Role        string
	CSRFToken   string
}
