package adminsession

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Anonymous implements the same surface as Service but treats every
// caller as already authenticated, for a deployment that gates access
// to the admin listener with a different mechanism entirely -- a VPN,
// an upstream SSO reverse proxy, network ACLs -- instead of this
// service's own OIDC login (spec section 14's ADMIN_AUTH_MODE). There
// is deliberately no way to "log out" of it, and BeginLogin/
// HandleCallback are dead routes that just bounce back to the console:
// ValidateSession always succeeds, so GET /api/v1/me always succeeds
// too, and the console's own login screen is never shown.
//
// This does not weaken anything the admin API itself enforces --
// CSRF protection, the administrator/viewer role split, and the audit
// trail all still apply, using the one fixed identity below. It only
// removes this service's own login gate; whatever fronts the admin
// listener is solely responsible for deciding who reaches it at all.
type Anonymous struct {
	info SessionInfo
}

// NewAnonymous builds the fixed identity every request resolves to.
// subject becomes every resulting audit_events.actor_subject -- pass
// something that identifies whatever perimeter actually authenticated
// the caller (e.g. "vpn", "sso-proxy"), not the literal default
// "anonymous", if the deployment can tell them apart; a shared,
// undifferentiated identity means the audit log can no longer
// distinguish which human took a given action, which is a real
// tradeoff a deployment choosing this mode is accepting.
func NewAnonymous(subject, displayName, role string) (*Anonymous, error) {
	csrfToken, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("adminsession: building anonymous identity: %w", err)
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("adminsession: building anonymous identity: %w", err)
	}
	return &Anonymous{info: SessionInfo{
		ID: id, Subject: subject, DisplayName: displayName, Role: role, CSRFToken: csrfToken,
	}}, nil
}

// BeginLogin has nothing to start -- it just bounces back to returnTo
// (or the console root), same validation as the real Service applies
// to its own post-login redirect.
func (a *Anonymous) BeginLogin(_ context.Context, returnTo string) (BeginLoginResult, error) {
	if !strings.HasPrefix(returnTo, "/") {
		returnTo = "/"
	}
	return BeginLoginResult{RedirectURL: returnTo}, nil
}

// HandleCallback is unreachable in normal operation -- nothing ever
// redirects here, since BeginLogin never starts a real OIDC transaction.
// Reports the same error a stale/replayed OIDC state would.
func (a *Anonymous) HandleCallback(_ context.Context, _, _ string) (string, string, error) {
	return "", "", ErrInvalidState
}

// ValidateSession ignores rawToken entirely -- every caller is the same
// fixed identity, regardless of whether an admin session cookie is even
// present.
func (a *Anonymous) ValidateSession(_ context.Context, _ string) (SessionInfo, error) {
	return a.info, nil
}

// Logout is a no-op success: there is no per-caller session state to
// destroy, and the admin listener's csrfProtected middleware already
// checked the CSRF token before this is ever called.
func (a *Anonymous) Logout(_ context.Context, _, _ string) error {
	return nil
}
