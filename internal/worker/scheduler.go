package worker

import (
	"context"
	"log"
	"time"

	"github.com/frid-iks/approve-auth/internal/metrics"
)

// Job is one scheduled retention/cleanup unit of work.
type Job struct {
	Name     string
	Interval time.Duration
	Run      func(ctx context.Context) error
}

// LockRunner is the internal/store.DB surface Scheduler needs to
// coordinate advisory locks across replicas -- see
// store.DB.WithAdvisoryLock.
type LockRunner interface {
	WithAdvisoryLock(ctx context.Context, key string, fn func(ctx context.Context) error) (ran bool, err error)
}

// Scheduler runs each Job on its own interval (once immediately, then
// on every tick), guarded by a named advisory lock so only one replica
// runs a given job at a time.
type Scheduler struct {
	db   LockRunner
	jobs []Job
}

func New(db LockRunner, jobs []Job) *Scheduler {
	return &Scheduler{db: db, jobs: jobs}
}

// Start launches one goroutine per job and returns immediately; every
// goroutine exits once ctx is canceled.
func (s *Scheduler) Start(ctx context.Context) {
	for _, job := range s.jobs {
		job := job
		go s.runLoop(ctx, job)
	}
}

func (s *Scheduler) runLoop(ctx context.Context, job Job) {
	ticker := time.NewTicker(job.Interval)
	defer ticker.Stop()
	for {
		s.runOnce(ctx, job)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Scheduler) runOnce(ctx context.Context, job Job) {
	ran, err := s.db.WithAdvisoryLock(ctx, "worker:"+job.Name, job.Run)
	if err != nil {
		log.Printf("worker: job %s failed: %v", job.Name, err)
		return
	}
	if ran {
		metrics.CleanupLastSuccessTimestamp.WithLabelValues(job.Name).Set(float64(time.Now().Unix()))
	}
	// ran == false (another replica holds the lock) is normal, not
	// worth logging every tick, and doesn't move the timestamp -- that
	// replica's own successful run already will.
}

// drainBatches repeatedly calls purge until a batch comes back smaller
// than batchSize (the backlog is drained) or maxBatches is hit (leaving
// the rest for the next tick, so one pathologically large backlog can't
// monopolize a job's goroutine indefinitely).
func drainBatches(ctx context.Context, batchSize, maxBatches int, purge func(context.Context, int) (int, error)) error {
	for i := 0; i < maxBatches; i++ {
		n, err := purge(ctx, batchSize)
		if err != nil {
			return err
		}
		if n < batchSize {
			return nil
		}
	}
	return nil
}
