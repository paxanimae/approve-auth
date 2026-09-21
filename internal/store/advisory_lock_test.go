package store_test

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/paxanimae/approve-auth/internal/store"
)

func TestWithAdvisoryLock_MutualExclusion(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

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
	db := openStoreAs(t, ctx, dbURL, "approve_auth_app", "devpassword")

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

// TestWithAdvisoryLock_ManyConcurrentJobsDoNotStarveASmallPool reproduces
// the incident that motivated pinning the lock's own connection outside
// db.Pool (see advisory_lock.go's doc comment): internal/worker's
// Scheduler starts every job's first run concurrently on startup, and
// each job's fn needs its own connection from db.Pool for its real work,
// on top of whichever connection is holding the advisory lock. Before
// that fix, enough concurrent callers -- exactly matching the pool's
// size, let alone exceeding it -- deadlocked every one of them: every
// available connection went to a lock-holder, and every lock-holder's fn
// then blocked forever waiting for a connection that would never free up.
func TestWithAdvisoryLock_ManyConcurrentJobsDoNotStarveASmallPool(t *testing.T) {
	dbURL := skipIfNoDB(t)
	ctx := context.Background()

	base := connString(t, dbURL, "approve_auth_app", "devpassword")
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parsing connection string: %v", err)
	}
	q := u.Query()
	q.Set("pool_max_conns", "4") // small enough that 9 concurrent callers used to deadlock it
	u.RawQuery = q.Encode()

	db, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(db.Close)

	const jobCount = 9 // matches internal/worker.Jobs' real job count
	var wg sync.WaitGroup
	errs := make(chan error, jobCount)
	for i := 0; i < jobCount; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := db.WithAdvisoryLock(ctx, fmt.Sprintf("test-many-concurrent-%d", i), func(ctx context.Context) error {
				// A real job's Run acquires its own connection from the
				// same pool to do its work -- reproduce that here instead
				// of using the lock-holding connection itself.
				var one int
				return db.Pool.QueryRow(ctx, "SELECT 1").Scan(&one)
			})
			errs <- err
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out: WithAdvisoryLock deadlocked a pool no larger than the number of concurrent callers")
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("WithAdvisoryLock: %v", err)
		}
	}
}
