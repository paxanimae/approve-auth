package enrollment

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/google/uuid"
)

// encryptEnvelope seals the raw credential token for the bounded claim-
// retry window (spec section 5/11). requestID and applicationID are
// authenticated as GCM additional data, not just embedded in the
// plaintext -- ciphertext that somehow got associated with the wrong
// request or application row fails to decrypt rather than silently
// returning a token for the wrong context.
func encryptEnvelope(key []byte, requestID, applicationID uuid.UUID, rawToken string) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("enrollment: envelope cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("enrollment: envelope GCM: %w", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("enrollment: envelope nonce: %w", err)
	}
	aad := envelopeAAD(requestID, applicationID)
	ciphertext = gcm.Seal(nil, nonce, []byte(rawToken), aad)
	return nonce, ciphertext, nil
}

func decryptEnvelope(key []byte, requestID, applicationID uuid.UUID, nonce, ciphertext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("enrollment: envelope cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("enrollment: envelope GCM: %w", err)
	}
	aad := envelopeAAD(requestID, applicationID)
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", fmt.Errorf("enrollment: envelope decryption failed: %w", err)
	}
	return string(plaintext), nil
}

func envelopeAAD(requestID, applicationID uuid.UUID) []byte {
	return []byte(requestID.String() + ":" + applicationID.String())
}
