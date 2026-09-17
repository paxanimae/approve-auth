package worker

import "context"

// Job is one scheduled unit of work (e.g. expiring claim envelopes,
// purging retention-expired rows). No implementation or scheduler exists
// yet -- see docs/threat-model.md and spec section 12 for what these will
// need to do.
type Job interface {
	Name() string
	Run(ctx context.Context) error
}
