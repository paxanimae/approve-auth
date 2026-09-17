package oidc

import "context"

// Identity is the (issuer, subject) pair the spec requires as the admin
// identity key (section 9) -- never an email-only key.
type Identity struct {
	Issuer      string
	Subject     string
	DisplayName string
	Groups      []string
}

// Client is the shape Milestone 4's admin OIDC login/callback will need.
// No implementation exists yet.
type Client interface {
	AuthURL(state, nonce, pkceChallenge string) string
	Exchange(ctx context.Context, code, pkceVerifier string) (Identity, error)
}
