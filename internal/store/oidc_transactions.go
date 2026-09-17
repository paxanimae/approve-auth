package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CreateOIDCTransaction persists the state needed to complete an admin
// login round trip (spec section 9): the PKCE verifier the callback will
// need, already encrypted by the caller (this package holds no key
// material, the same separation as claim_results).
func (db *DB) CreateOIDCTransaction(ctx context.Context, stateHash []byte, nonce string, encryptedPKCEVerifier []byte, safeReturnPath string, expiresAt time.Time) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO oidc_transactions (state_hash, nonce, encrypted_pkce_verifier, safe_return_path, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		stateHash, nonce, encryptedPKCEVerifier, nullableText(safeReturnPath), expiresAt)
	if err != nil {
		return fmt.Errorf("store: creating oidc transaction: %w", err)
	}
	return nil
}

// ConsumeOIDCTransaction atomically looks up and consumes a transaction
// by state hash -- single-use, per spec section 9. (_, false, nil) covers
// not-found, already-consumed, and expired uniformly; the callback
// handler doesn't need to distinguish them, it just restarts login.
func (db *DB) ConsumeOIDCTransaction(ctx context.Context, stateHash []byte) (OIDCTransaction, bool, error) {
	var tx OIDCTransaction
	err := db.Pool.QueryRow(ctx, `
		UPDATE oidc_transactions
		SET consumed_at = now()
		WHERE state_hash = $1 AND consumed_at IS NULL AND expires_at > now()
		RETURNING state_hash, nonce, encrypted_pkce_verifier, safe_return_path, expires_at, consumed_at`,
		stateHash,
	).Scan(&tx.StateHash, &tx.Nonce, &tx.EncryptedPKCEVerifier, &tx.SafeReturnPath, &tx.ExpiresAt, &tx.ConsumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return OIDCTransaction{}, false, nil
	}
	if err != nil {
		return OIDCTransaction{}, false, fmt.Errorf("store: consuming oidc transaction: %w", err)
	}
	return tx, true, nil
}
