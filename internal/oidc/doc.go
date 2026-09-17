// Package oidc will wrap the Authorization Code + PKCE flow against the
// organizational OIDC provider (spec section 9). Deliberately no
// go-oidc/oauth2 dependency yet -- pinning one now would be speculative
// before Milestone 4 designs the concrete flow. Client is an interface
// only, so other packages can depend on the shape without the
// implementation existing.
package oidc
