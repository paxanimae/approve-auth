# Release notes -- v1.0 (Milestones 1-5, Milestone 6 in progress)

Date: 2026-09-17.

## What this release is

A production-oriented Go + PostgreSQL + Svelte service that lets an
administrator manually approve one browser (e.g. a reception TV) for
time-limited access to one Traefik-protected application hostname, via
ForwardAuth. Traefik remains the sole reverse proxy; this service owns
authorization decisions, approval requests, credentials, administration,
and the audit trail. See `README.md` for the architecture diagram and
repository layout, and this build's product spec for the full contract
(not checked into this repo).

## Delivered

- **ForwardAuth authorization decision** (`internal/authz`): the
  authoritative allow/deny check from the product spec, evaluated
  against one consistent PostgreSQL read, fail-closed on any error or
  timeout. Verified against a real Traefik instance and a real backend,
  not mocks (`tests/integration/`).
- **Enrollment and lifecycle** (`internal/enrollment`): request/waiting/
  status/cancel/claim/ack/logout, CSRF-protected, rate-limited
  (bootstrap, status, and pending-submission limits all enforced), with
  a retry-safe encrypted claim envelope proven correct under genuine
  concurrency (`internal/store/race_test.go`). The waiting page works
  fully without JavaScript and, when JavaScript is available, polls on
  the spec's real schedule (5s+jitter, backing off on failure, pausing
  while hidden) instead of a fixed dumb reload.
- **Admin product**: real OIDC Authorization Code + PKCE login
  (`internal/oidc`, `internal/adminsession`) against a mature library,
  never hand-rolled JWT verification; role-based access (viewer/
  administrator); a CSRF-protected admin API covering applications,
  requests, authorizations (including bulk renew/revoke), and the audit
  log with CSV export; and a minimal but functional Svelte admin
  console served straight out of the Go binary.
- **Operations**: a real retention/cleanup worker
  (`internal/worker`/`internal/store/retention.go`) coordinated across
  replicas via Postgres advisory locks, Prometheus metrics and a real
  `GET /readyz` on the Operations listener, and a Docker Swarm
  deployment manifest (`deploy/stack.yml`) with accompanying runbooks.
- **Security posture**: CSP/Referrer-Policy/X-Content-Type-Options on
  every browser-facing response; zero known vulnerabilities in the
  dependency graph (`govulncheck`) or the built runtime image
  (`docker scout cves`) as of this date; a self-review pass against
  OWASP Top 10 (`docs/security-review.md`).

## Bugs fixed during this release cycle (worth knowing about)

- `GET /status` and `POST /requests` were serializing Go structs with no
  `json` tags, so their wire fields came out in PascalCase instead of
  the spec's required snake_case -- fixed; see `internal/enrollment/types.go`.
- The waiting page's JavaScript-enhanced status polling (a named,
  specific requirement) had never actually been implemented, only its
  no-JS fallback -- fixed in `web/public/assets/app.js`.
- `POST /auth/logout` was reachable without a CSRF token at all, despite
  the spec explicitly calling out logout as needing CSRF protection like
  every other mutation -- fixed with a dedicated `csrfProtected`
  middleware chain that doesn't also require the administrator role
  (either role may log itself out).
- The bootstrap (30/minute/IP) and status (20/minute/pending-proof) rate
  limits had configuration settings defined since the very first
  milestone but were never actually read or enforced by anything --
  fixed in `internal/enrollment`.
- No response anywhere set `Content-Security-Policy`, `Referrer-Policy`,
  or `X-Content-Type-Options` -- fixed via `internal/httpserver.securityHeaders`.

## Known limitations

See `docs/acceptance-criteria.md` for the full spec-section-17 sign-off
walkthrough. In summary, everything below is a real, specific,
tracked gap, not an unknown unknown:

- No dedicated "Expiring soon" console view with its full filter/sort
  set yet -- the underlying list/bulk-action API is done and tested.
- No manual TV-browser UX/accessibility review has been performed.
- The Swarm deployment manifest is schema-validated and reasoned
  through but has never been deployed to a real multi-node cluster; the
  backup-restore drill and the load test have never been run. All three
  have a written runbook/plan, not yet a result.
- No structured JSON logging with correlation IDs (plain `log.Printf`
  today) and no dashboards (no committed Grafana JSON or similar).
- The admin API's `Idempotency-Key` replay semantics from the spec are
  not implemented; optimistic-concurrency version checks prevent a
  stale resubmission from silently double-applying, but a byte-for-byte
  identical retry isn't deduplicated.

## Upgrading

There is no prior release to upgrade from -- this is the first. Future
releases should append here rather than editing this section, and
should record the migration path (schema changes, config changes)
explicitly, the way `docs/runbooks/rollout-rollback.md`'s rolling-
upgrade section describes.
