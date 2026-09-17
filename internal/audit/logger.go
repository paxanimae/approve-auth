package audit

import (
	"context"
	"net"

	"github.com/google/uuid"
)

// Event is one audit_events row (spec section 8/12). Mutations and their
// audit event must commit together -- callers are expected to write both
// within the same database transaction once a later milestone adds the
// business logic that produces these.
type Event struct {
	ActorType       string
	ActorSubject    string
	Action          string
	ApplicationID   *uuid.UUID
	RequestID       *uuid.UUID
	AuthorizationID *uuid.UUID
	CorrelationID   uuid.UUID
	SourceIP        net.IP
	Reason          string
	RedactedBefore  []byte // JSON
	RedactedAfter   []byte // JSON
	Outcome         string
}

// Logger records audit events. The only implementation today is
// PostgresLogger; the interface exists so callers in other packages don't
// need to import pgx directly.
type Logger interface {
	Record(ctx context.Context, e Event) error
}
