// Package worker runs the retention/cleanup jobs from spec section 12
// against PostgreSQL, using advisory locks (see internal/store.
// WithAdvisoryLock) and bounded batches (spec section 2). It never
// affects any access decision: internal/authz's ForwardAuth check
// already derives allow/deny purely from live database timestamps, so a
// worker that falls behind or stops entirely cannot extend permission
// (spec section 7) -- these jobs only mark terminal workflow state,
// write idempotent audit events, and purge/redact data past its
// retention window.
//
// Audit-log purging is deliberately not one of these jobs: only the
// separate app_maintenance database role may delete audit_events (spec
// section 11, control 10, enforced by migration 000012's grants), so it
// runs instead as its own one-shot operator command --
// `admin purge-audit-log` -- the same separation cmd/admin's
// migrate-up/migrate-down already use for privilege reasons.
package worker
