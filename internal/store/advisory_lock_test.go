package store_test

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestWithAdvisoryLock_MutualExclusion(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	var wg sync.WaitGroup
	holding := make(chan struct{})
	release := make(chan struct{})
	var firstRan bool

	wg.Add(1)
	go func() {
		defer wg.Done()
		ran, err := db.WithAdvisoryLock(ctx, "test-mutual-exclusion", func(ctx context.Context) error {
			firstRan = true
			close(holding)
			<-release
			return nil
		})
		if err != nil {
			t.Errorf("first WithAdvisoryLock: %v", err)
		}
		if !ran {
			t.Error("first WithAdvisoryLock should have acquired the lock")
		}
	}()

	<-holding // wait until the first call is inside its critical section

	ran, err := db.WithAdvisoryLock(ctx, "test-mutual-exclusion", func(ctx context.Context) error {
		t.Error("second WithAdvisoryLock should not have run concurrently with the first")
		return nil
	})
	if err != nil {
		t.Fatalf("second WithAdvisoryLock: %v", err)
	}
	if ran {
		t.Error("second WithAdvisoryLock should not have acquired the lock while the first holds it")
	}
	close(release)
	wg.Wait()

	if !firstRan {
		t.Error("first WithAdvisoryLock's fn never ran")
	}

	// Once released, a third call must be able to acquire it.
	ran, err = db.WithAdvisoryLock(ctx, "test-mutual-exclusion", func(ctx context.Context) error { return nil })
	if err != nil {
		t.Fatalf("third WithAdvisoryLock: %v", err)
	}
	if !ran {
		t.Error("third WithAdvisoryLock should have acquired the now-released lock")
	}
}

func TestWithAdvisoryLock_DifferentKeysDoNotContend(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "manual_approval_app", "devpassword")

	holding := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_, _ = db.WithAdvisoryLock(ctx, "test-key-a", func(ctx context.Context) error {
			close(holding)
			<-release
			return nil
		})
	}()

	<-holding
	defer close(release)

	done := make(chan bool, 1)
	go func() {
		ran, err := db.WithAdvisoryLock(ctx, "test-key-b", func(ctx context.Context) error { return nil })
		if err != nil {
			t.Errorf("WithAdvisoryLock (different key): %v", err)
		}
		done <- ran
	}()

	select {
	case ran := <-done:
		if !ran {
			t.Error("a different lock key should not contend with the held one")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the different-key lock -- it should not be blocked by the other key")
	}
}
