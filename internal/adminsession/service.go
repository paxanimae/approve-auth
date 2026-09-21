package adminsession

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidState = errors.New("adminsession: invalid, expired, or already-used OIDC state")
	// ErrNoAccess means the identity authenticated successfully but is
	// not a member of any allowlisted group (spec section 9: "Default is
	// no access").
	ErrNoAccess    = errors.New("adminsession: identity is not a member of any allowlisted group")
	ErrNoSession   = errors.New("adminsession: no active admin session")
	ErrIdleTimeout = errors.New("adminsession: session idle timeout exceeded")
	ErrInvalidCSRF = errors.New("adminsession: invalid or missing CSRF token")
)

type Service struct {
	store      Store
	oidcClient OIDCClient
	cfg        Config
}

func New(s Store, oidcClient OIDCClient, cfg Config) *Service {
	return &Service{store: s, oidcClient: oidcClient, cfg: cfg}
}

// BeginLogin starts the Authorization Code + PKCE flow (spec section 9).
// Unlike internal/enrollment's pending-proof pattern, no cookie is set
// here at all: the state parameter round-trips through the IdP's
// redirect and callback URL itself, and everything else needed to
// complete the flow is stored server-side keyed by its hash.
func (s *Service) BeginLogin(ctx context.Context, returnTo string) (BeginLoginResult, error) {
	state, err := generateToken()
	if err != nil {
		return BeginLoginResult{}, err
	}
	nonce, err := generateToken()
	if err != nil {
		return BeginLoginResult{}, err
	}
	verifier, err := generateToken()
	if err != nil {
		return BeginLoginResult{}, err
	}

	stateHash := hashToken(state)
	encryptedVerifier, err := encryptPKCEVerifier(s.cfg.StateEncryptionKey, stateHash, verifier)
	if err != nil {
		return BeginLoginResult{}, err
	}

	if err := s.store.CreateOIDCTransaction(ctx, stateHash, nonce, encryptedVerifier, validateAdminReturnPath(returnTo), time.Now().Add(s.cfg.TransactionTTL)); err != nil {
		return BeginLoginResult{}, fmt.Errorf("adminsession: begin login: %w", err)
	}

	return BeginLoginResult{RedirectURL: s.oidcClient.AuthURL(state, nonce, pkceChallenge(verifier))}, nil
}

// HandleCallback completes the flow: consumes the (single-use) state,
// decrypts the PKCE verifier, exchanges the code, maps the identity's
// groups to a role, and creates the admin session. Returns the raw
// session cookie value and the validated return path.
func (s *Service) HandleCallback(ctx context.Context, state, code string) (rawSessionToken, returnPath string, err error) {
	stateHash := hashToken(state)
	txn, found, err := s.store.ConsumeOIDCTransaction(ctx, stateHash)
	if err != nil {
		return "", "", fmt.Errorf("adminsession: callback: %w", err)
	}
	if !found {
		return "", "", ErrInvalidState
	}

	verifier, err := decryptPKCEVerifier(s.cfg.StateEncryptionKey, stateHash, txn.EncryptedPKCEVerifier)
	if err != nil {
		return "", "", fmt.Errorf("adminsession: callback: %w", err)
	}

	identity, err := s.oidcClient.Exchange(ctx, code, verifier, txn.Nonce)
	if err != nil {
		return "", "", fmt.Errorf("adminsession: callback: exchanging code: %w", err)
	}

	role := s.mapRole(identity.Groups)
	if role == "" {
		// Not an administrator or viewer by OIDC group -- check whether
		// they own at least one application instead of denying outright.
		// Only whether they qualify for this role at all is snapshotted
		// here (matching how administrator/viewer already work); which
		// specific application(s) they own is resolved fresh on every
		// request that needs it (migration 000016's own comment).
		owned, err := s.store.GetOwnedApplicationIDs(ctx, identity.Subject)
		if err != nil {
			return "", "", fmt.Errorf("adminsession: callback: checking application ownership: %w", err)
		}
		if len(owned) == 0 {
			return "", "", ErrNoAccess
		}
		role = "application_owner"
	}

	rawToken, err := generateToken()
	if err != nil {
		return "", "", err
	}
	csrfSecret, err := generateToken()
	if err != nil {
		return "", "", err
	}

	if _, err := s.store.CreateAdminSession(ctx, identity.Issuer, identity.Subject, identity.DisplayName, role,
		hashToken(rawToken), []byte(csrfSecret), time.Now().Add(s.cfg.AbsoluteTTL)); err != nil {
		return "", "", fmt.Errorf("adminsession: callback: %w", err)
	}

	returnPath = "/"
	if txn.SafeReturnPath != nil && *txn.SafeReturnPath != "" {
		returnPath = *txn.SafeReturnPath
	}
	return rawToken, returnPath, nil
}

// ValidateSession enforces both TTLs from spec section 14: absolute
// (checked in SQL by GetLiveAdminSessionByTokenHash) and idle (checked
// here against LastSeenAt, since it's a config value, not schema).
func (s *Service) ValidateSession(ctx context.Context, rawToken string) (SessionInfo, error) {
	if rawToken == "" {
		return SessionInfo{}, ErrNoSession
	}
	sess, found, err := s.store.GetLiveAdminSessionByTokenHash(ctx, hashToken(rawToken))
	if err != nil {
		return SessionInfo{}, fmt.Errorf("adminsession: validate: %w", err)
	}
	if !found {
		return SessionInfo{}, ErrNoSession
	}

	lastActivity := sess.CreatedAt
	if sess.LastSeenAt != nil {
		lastActivity = *sess.LastSeenAt
	}
	if time.Now().After(lastActivity.Add(s.cfg.IdleTTL)) {
		return SessionInfo{}, ErrIdleTimeout
	}

	// Advisory, same as internal/authz's last-seen touch: failure here
	// must not deny an otherwise-valid session.
	_ = s.store.TouchAdminSessionLastSeen(ctx, sess.ID)

	displayName := ""
	if sess.DisplayName != nil {
		displayName = *sess.DisplayName
	}
	return SessionInfo{ID: sess.ID, Subject: sess.OIDCSubject, DisplayName: displayName, Role: sess.Role, CSRFToken: csrfToken(sess.CSRFSecret)}, nil
}

// Logout requires the session's own CSRF token (spec section 9: "CSRF
// protection for every mutation, including logout") -- validated here,
// against the secret this same lookup just loaded, rather than trusting a
// token the HTTP layer computed separately.
func (s *Service) Logout(ctx context.Context, rawToken, csrfToken string) error {
	if rawToken == "" {
		return nil
	}
	sess, found, err := s.store.GetLiveAdminSessionByTokenHash(ctx, hashToken(rawToken))
	if err != nil {
		return fmt.Errorf("adminsession: logout: %w", err)
	}
	if !found {
		return nil
	}
	if !validCSRFToken(sess.CSRFSecret, csrfToken) {
		return ErrInvalidCSRF
	}
	if err := s.store.RevokeAdminSession(ctx, sess.ID); err != nil {
		return fmt.Errorf("adminsession: logout: %w", err)
	}
	return nil
}

// mapRole implements spec section 9's group -> role mapping. A member of
// both groups gets the more privileged role; a member of neither gets
// "" (no access).
func (s *Service) mapRole(groups []string) string {
	member := make(map[string]bool, len(groups))
	for _, g := range groups {
		member[g] = true
	}
	for _, g := range s.cfg.OIDCAdminGroups {
		if member[g] {
			return "administrator"
		}
	}
	for _, g := range s.cfg.OIDCViewerGroups {
		if member[g] {
			return "viewer"
		}
	}
	return ""
}
