package worker_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/paxanimae/approve-auth/internal/worker"
)

// fakeLockRunner is an in-memory stand-in for store.DB.WithAdvisoryLock,
// so Scheduler's own run-and-reschedule logic can be tested without a
// database. It grants the lock to at most one caller per key at a time,
// the same mutual-exclusion contract the real Postgres-backed
// implementation provides.
type fakeLockRunner struct {
	mu     sync.Mutex
	locked map[string]bool
}

func newFakeLockRunner() *fakeLockRunner { return &fakeLockRunner{locked: map[string]bool{}} }

func (f *fakeLockRunner) WithAdvisoryLock(ctx context.Context, key string, fn func(ctx context.Context) error) (bool, error) {
	f.mu.Lock()
	if f.locked[key] {
		f.mu.Unlock()
		return false, nil
	}
	f.locked[key] = true
	f.mu.Unlock()

	defer func() {
		f.mu.Lock()
		f.locked[key] = false
		f.mu.Unlock()
	}()
	return true, fn(ctx)
}

func TestScheduler_RunsEachJobImmediatelyAndOnEveryTick(t *testing.T) {
	lock := newFakeLockRunner()
	var mu sync.Mutex
	runs := 0

	job := worker.Job{
		Name: "test-job", Interval: 20 * time.Millisecond,
		Run: func(ctx context.Context) error {
			mu.Lock()
			runs++
			mu.Unlock()
			return nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	worker.New(lock, []worker.Job{job}).Start(ctx)

	time.Sleep(90 * time.Millisecond)
	cancel()
	time.Sleep(10 * time.Millisecond) // let the goroutine observe ctx.Done and exit

	mu.Lock()
	got := runs
	mu.Unlock()
	if got < 3 {
		t.Errorf("job ran %d times in ~90ms with a 20ms interval (including an immediate first run), want at least 3", got)
	}
}

func TestScheduler_JobErrorDoesNotStopFutureTicks(t *testing.T) {
	lock := newFakeLockRunner()
	var mu sync.Mutex
	runs := 0

	job := worker.Job{
		Name: "failing-job", Interval: 15 * time.Millisecond,
		Run: func(ctx context.Context) error {
			mu.Lock()
			runs++
			mu.Unlock()
			return errors.New("boom")
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	worker.New(lock, []worker.Job{job}).Start(ctx)

	time.Sleep(80 * time.Millisecond)

	mu.Lock()
	got := runs
	mu.Unlock()
	if got < 3 {
		t.Errorf("job ran %d times despite always erroring, want at least 3 (an error must not stop the ticker)", got)
	}
}

func TestScheduler_RunsIndependentJobsConcurrently(t *testing.T) {
	lock := newFakeLockRunner()
	var mu sync.Mutex
	names := map[string]int{}

	makeJob := func(name string) worker.Job {
		return worker.Job{
			Name: name, Interval: time.Hour, // only care about the immediate first run
			Run: func(ctx context.Context) error {
				mu.Lock()
				names[name]++
				mu.Unlock()
				return nil
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	worker.New(lock, []worker.Job{makeJob("a"), makeJob("b"), makeJob("c")}).Start(ctx)

	time.Sleep(30 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	for _, name := range []string{"a", "b", "c"} {
		if names[name] != 1 {
			t.Errorf("job %s ran %d times, want exactly 1 (its immediate first run)", name, names[name])
		}
	}
}
