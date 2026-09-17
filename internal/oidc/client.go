// Package oidc wraps the Authorization Code + PKCE flow against the
// organizational OIDC provider (spec section 9), using a mature library
// (coreos/go-oidc + golang.org/x/oauth2) rather than hand-rolled JWT
// verification -- spec section 9 is explicit about this.
package oidc

import (
	"context"
	"fmt"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Identity is the (issuer, subject) pair spec section 9 requires as the
// admin identity key -- never an email-only key -- plus what the caller
// needs to map to a role and display.
type Identity struct {
	Issuer      string
	Subject     string
	DisplayName string
	Groups      []string
}

// Client is the shape the admin login/callback handlers need. Defined as
// an interface so internal/adminsession's tests can substitute a fake
// without a real IdP.
type Client interface {
	AuthURL(state, nonce, pkceChallenge string) string
	// Exchange validates the callback's code, verifies the ID token
	// (issuer/audience/signature/expiry -- go-oidc's job) and its nonce
	// against expectedNonce, and returns the resulting identity.
	Exchange(ctx context.Context, code, pkceVerifier, expectedNonce string) (Identity, error)
}

type client struct {
	provider     *gooidc.Provider
	verifier     *gooidc.IDTokenVerifier
	oauth2Config oauth2.Config
}

// NewClient discovers the provider's configuration (spec section 9:
// "issuer/audience/signature/expiry validation" via the provider's own
// published JWKS) and builds the Authorization Code + PKCE client.
func NewClient(ctx context.Context, issuer, clientID, clientSecret, redirectURL string) (Client, error) {
	provider, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovering provider %s: %w", issuer, err)
	}
	return &client{
		provider: provider,
		verifier: provider.Verifier(&gooidc.Config{ClientID: clientID}),
		oauth2Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{gooidc.ScopeOpenID, "profile", "email", "groups"},
		},
	}, nil
}

func (c *client) AuthURL(state, nonce, pkceChallenge string) string {
	return c.oauth2Config.AuthCodeURL(state,
		gooidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (c *client) Exchange(ctx context.Context, code, pkceVerifier, expectedNonce string) (Identity, error) {
	token, err := c.oauth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", pkceVerifier))
	if err != nil {
		return Identity{}, fmt.Errorf("oidc: exchanging code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, fmt.Errorf("oidc: token response had no id_token")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("oidc: verifying id_token: %w", err)
	}
	if idToken.Nonce != expectedNonce {
		return Identity{}, fmt.Errorf("oidc: id_token nonce does not match the expected one")
	}

	var claims struct {
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("oidc: parsing id_token claims: %w", err)
	}

	return Identity{
		Issuer:      idToken.Issuer,
		Subject:     idToken.Subject,
		DisplayName: claims.Name,
		Groups:      claims.Groups,
	}, nil
}
