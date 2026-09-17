package store_test

import (
	"context"
	"crypto/sha256"
	"sync"
	"testing"
	"time"
)

// TestRace_ConcurrentClaimCreatesExactlyOneCredential simulates the
// double-click/retry-in-flight case spec section 16's verification plan
// calls out ("claim vs disable" and friends): two goroutines racing to
// claim the same approved request must not both succeed in minting a
// credential. The row lock ClaimApproved takes (FOR UPDATE OF r) is what
// serializes this, not application-level coordination -- this test is
// here to prove that lock actually does its job under real concurrent
// access, not just when called twice sequentially (already covered in
// lifecycle_test.go).
func TestRace_ConcurrentClaimCreatesExactlyOneCredential(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "manual_approval_app", "devpassword")
	conn := connectAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	appID := insertApplication(t, ctx, conn, "race-claim.example.test")
	reqIDStr := insertApprovalRequest(t, ctx, conn, appID, t.Name())
	reqID := mustParseUUID(t, reqIDStr)
	authID := insertAuthorization(t, ctx, conn, appID, reqIDStr, authorizationOpts{
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	})
	// approval_requests.status must be 'approved' with a future
	// claim_deadline_at for ClaimApproved to accept it -- insertAuthorization
	// doesn't touch the request row, so set that directly.
	if _, err := conn.Exec(ctx, `UPDATE approval_requests SET status = 'approved', claim_deadline_at = now() + interval '30 minutes' WHERE id = $1`, reqID); err != nil {
		t.Fatalf("marking request approved: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(ctx, `DELETE FROM credentials WHERE authorization_id = $1`, authID) })

	const attempts = 8
	var wg sync.WaitGroup
	alreadyClaimedCount := make([]bool, attempts)
	errs := make([]error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tokenHash := sha256.Sum256([]byte(t.Name() + string(rune('a'+i))))
			_, _, alreadyClaimed, err := db.ClaimApproved(ctx, reqID, tokenHash[:], 365*24*time.Hour)
			alreadyClaimedCount[i] = alreadyClaimed
			errs[i] = err
		}(i)
	}
	wg.Wait()

	freshClaims := 0
	for i := 0; i < attempts; i++ {
		if errs[i] != nil {
			t.Errorf("attempt %d: unexpected error: %v", i, errs[i])
			continue
		}
		if !alreadyClaimedCount[i] {
			freshClaims++
		}
	}
	if freshClaims != 1 {
		t.Errorf("fresh (non-alreadyClaimed) claims = %d, want exactly 1 out of %d concurrent attempts", freshClaims, attempts)
	}

	var credentialCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE authorization_id = $1`, authID).Scan(&credentialCount); err != nil {
		t.Fatalf("counting credentials: %v", err)
	}
	if credentialCount != 1 {
		t.Errorf("credential count after %d concurrent claims = %d, want 1", attempts, credentialCount)
	}
}
