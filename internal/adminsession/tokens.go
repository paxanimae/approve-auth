package adminsession

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// generateToken returns a 32-byte cryptographically random value,
// base64url-encoded without padding -- 43 characters, which also
// satisfies PKCE's code_verifier length/character-set requirements
// (RFC 7636), so the same generator serves both the opaque session/state
// tokens and the PKCE verifier.
func generateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("adminsession: generating random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// pkceChallenge implements RFC 7636's S256 method.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// encryptPKCEVerifier / decryptPKCEVerifier seal the PKCE verifier for
// the round trip through the browser's OIDC redirect (spec section 14's
// OIDC_STATE_ENCRYPTION_KEY_FILE). The GCM nonce is derived from the
// transaction's own state hash rather than stored separately -- the
// oidc_transactions schema has no separate nonce column for this, and
// each transaction's state_hash is unique by construction (unique
// index), so reusing 12 bytes of it as the nonce never repeats under the
// same key.
func encryptPKCEVerifier(key, stateHash []byte, verifier string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := stateHash[:gcm.NonceSize()]
	return gcm.Seal(nil, nonce, []byte(verifier), nil), nil
}

func decryptPKCEVerifier(key, stateHash, ciphertext []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := stateHash[:gcm.NonceSize()]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("adminsession: decrypting PKCE verifier: %w", err)
	}
	return string(plaintext), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("adminsession: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("adminsession: GCM: %w", err)
	}
	return gcm, nil
}
