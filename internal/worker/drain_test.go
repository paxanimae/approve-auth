package worker

import (
	"context"
	"errors"
	"testing"
)

func TestDrainBatches_StopsWhenABatchIsSmallerThanBatchSize(t *testing.T) {
	ctx := context.Background()
	remaining := 250
	calls := 0

	err := drainBatches(ctx, 100, 10, func(ctx context.Context, limit int) (int, error) {
		calls++
		n := remaining
		if n > limit {
			n = limit
		}
		remaining -= n
		return n, nil
	})
	if err != nil {
		t.Fatalf("drainBatches: %v", err)
	}
	// 250 drained as 100 + 100 + 50 -- the 50 (< batchSize) ends the loop.
	if calls != 3 {
		t.Errorf("purge called %d times, want 3", calls)
	}
	if remaining != 0 {
		t.Errorf("remaining = %d, want 0 (fully drained)", remaining)
	}
}

func TestDrainBatches_StopsAtMaxBatchesOnAnEndlessBacklog(t *testing.T) {
	ctx := context.Background()
	calls := 0

	err := drainBatches(ctx, 100, 5, func(ctx context.Context, limit int) (int, error) {
		calls++
		return limit, nil // always claims a full batch -- backlog never runs out
	})
	if err != nil {
		t.Fatalf("drainBatches: %v", err)
	}
	if calls != 5 {
		t.Errorf("purge called %d times, want exactly maxBatches (5)", calls)
	}
}

func TestDrainBatches_PropagatesError(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("db unavailable")
	calls := 0

	err := drainBatches(ctx, 100, 10, func(ctx context.Context, limit int) (int, error) {
		calls++
		return 0, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Errorf("drainBatches error = %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Errorf("purge called %d times, want 1 (stop immediately on error)", calls)
	}
}
