package enrollment

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// csrfToken derives a synchronizer token from the enrollment context's
// stored secret -- deterministic, so the same rendered form token stays
// valid for the context's whole lifetime without a separate per-render
// nonce store. An attacker can't compute this without already knowing
// secret, which only this server and the legitimate browser's HttpOnly
// cookie-backed context ever see.
func csrfToken(secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("manual-approval-csrf"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func validCSRFToken(secret []byte, candidate string) bool {
	want := csrfToken(secret)
	return subtle.ConstantTimeCompare([]byte(want), []byte(candidate)) == 1
}
