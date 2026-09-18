package adminsession

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// csrfToken derives a synchronizer token from the admin session's stored
// secret -- the same deterministic-HMAC approach as
// internal/enrollment's CSRF tokens (duplicated rather than shared: it's
// ten lines, and the two packages' session lifetimes and stores are
// otherwise unrelated).
func csrfToken(secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("approve-auth-admin-csrf"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func validCSRFToken(secret []byte, candidate string) bool {
	want := csrfToken(secret)
	return subtle.ConstantTimeCompare([]byte(want), []byte(candidate)) == 1
}
