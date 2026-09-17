package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// generateRawToken returns a 32-byte cryptographically random value,
// base64url-encoded without padding (spec section 4: "32 cryptographically
// random bytes, base64url without padding"). Used for both the pending
// proof and the access credential -- the two are never confused because
// they're hashed into different tables.
func generateRawToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("enrollment: generating random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// generateCSRFSecret returns 32 random bytes to store alongside an
// enrollment context; verificationCode below is unrelated (it's a
// comparison aid, never a secret) and uses a much smaller, human-typeable
// alphabet instead.
func generateCSRFSecret() ([]byte, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("enrollment: generating CSRF secret: %w", err)
	}
	return buf, nil
}

// verificationCodeAlphabet excludes visually ambiguous characters
// (0/O, 1/I/L) -- this code is read aloud or typed by a human comparing
// it against a screen, never used as a lookup key (spec section 5).
const verificationCodeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// generateVerificationCode returns e.g. "K7MP-4Q2D".
func generateVerificationCode() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("enrollment: generating verification code: %w", err)
	}
	out := make([]byte, 9)
	for i, b := range buf {
		if i == 4 {
			out[4] = '-'
		}
		pos := i
		if i >= 4 {
			pos++
		}
		out[pos] = verificationCodeAlphabet[int(b)%len(verificationCodeAlphabet)]
	}
	return string(out), nil
}
