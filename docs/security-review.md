# Security review

Status: self-review pass, dated 2026-09-17, for Milestone 6's "security
review, dependency/image scans" deliverable. This is not an independent
third-party audit -- it's the same team that wrote the code walking
through OWASP Top 10 (2021) categories and this project's own dependency
graph, cross-referenced against `docs/threat-model.md`'s existing
per-threat table rather than repeating it. Get an independent review
before a real production release if the deployment's risk profile
warrants it; this document doesn't substitute for one.

## Dependency and image scans

| Scan | Tool | Result | Date |
|---|---|---|---|
| Go module graph | `govulncheck ./...` | No vulnerabilities found | 2026-09-17 |
| Production runtime image (`Dockerfile`'s `runtime` target) | `docker scout cves` | 0 critical / 0 high / 0 medium / 0 low across 29 packages, 22 MB image | 2026-09-17 |

Both are point-in-time results, not a standing guarantee -- new CVEs get
disclosed against existing code constantly. Re-run both:

```bash
# Module graph (govulncheck needs Go >=1.26 itself; the project's own
# pinned toolchain, golang:1.25.14, is unaffected -- this is a separate
# scanning tool's requirement, not a project dependency change).
docker run --rm -v "$(pwd):/workspace" -w /workspace golang:1.26 \
  sh -c 'go install golang.org/x/vuln/cmd/govulncheck@latest && /root/go/bin/govulncheck ./...'

# Image (build the runtime target first, then scan it)
docker build -t manual-approval:scan --target runtime .
docker scout cves manual-approval:scan
docker rmi manual-approval:scan
```

before every release, and ideally on a schedule (a CI job on a cron
trigger, not wired up yet -- see "Gaps" below).

## OWASP Top 10 (2021) walkthrough

**A01 Broken Access Control.** The ForwardAuth authoritative check
(spec section 3) is the core of this service's whole purpose --
covered exhaustively in `docs/threat-model.md` section 4's first several
rows, including composite-FK cross-application isolation and the
genuine-concurrency race test. Admin-side: role checks
(`requireAdministrator`) and CSRF (`requireAdminCSRF`) gate every
mutation; `internal/httpserver/admin_handlers_test.go` proves a viewer
session gets 403 on a mutating endpoint. No endpoint trusts a
browser-supplied identity claim (spec section 11 control 5) -- identity
always comes from a server-side session/cookie lookup, never a header
or body field the caller controls.

**A02 Cryptographic Failures.** Access/pending/admin-session tokens are
32 random bytes, compared only as SHA-256 hashes at rest (never stored
or logged in plaintext) -- `internal/enrollment/tokens.go`,
`internal/adminsession/tokens.go`. The one deliberate plaintext
exception, the 10-minute claim-retry envelope, uses AES-256-GCM with
request/application IDs as authenticated additional data, so a
ciphertext associated with the wrong row fails to decrypt rather than
silently succeeding (tested in `internal/enrollment/service_test.go`).
CSRF tokens are HMAC-derived, compared in constant time
(`crypto/subtle.ConstantTimeCompare`) everywhere they're checked. TLS is
mandatory on every browser-facing listener and the mTLS Authorization
listener explicitly sets `MinVersion: tls.VersionTLS12` and never sets
`InsecureSkipVerify`.

**A03 Injection.** Every database call in `internal/store` uses
parameterized queries (`$1`, `$2`, ...) via `pgx` -- grep confirms no
string-concatenated SQL anywhere in the codebase. `internal/enrollment`
and `internal/httpserver` treat every field spec section 10 says to
treat as "escaped, untrusted content" (labels, messages, denial
reasons) as plain data, never interpolated into a template as raw HTML
(Go's `html/template`, used for every server-rendered page, escapes by
default -- this project never uses `html/template.HTML` or similar
escape-bypassing wrappers to defeat that). CSV export
(`exportAuditEventsHandler`) sanitizes leading `=`/`+`/`-`/`@`/tab/CR to
block spreadsheet-formula injection (spec section 9/11), tested in
`internal/httpserver/admin_handlers_test.go`.

**A04 Insecure Design.** This is what most of `docs/threat-model.md`
and the spec itself already are -- fail-closed on DB/decision-timeout
failures (503, never a silent allow), no positive authorization cache,
optimistic-concurrency version checks on every admin mutation, and the
composite-FK application-consistency invariants enforced at the
database level rather than only in application code (so a bug in one
call site can't silently create a cross-application credential).

**A05 Security Misconfiguration.** `internal/config.Validate()`
aggregates every configuration problem at startup and refuses to bind
any listener on failure (spec section 14: "invalid security
configuration prevents readiness"). Secrets are rejected outright if
the bare (non-`_FILE`) environment variable is set at all, closing the
"secret accidentally passed as a plain env var" misconfiguration class
rather than just documenting against it. `internal/httpserver.securityHeaders`
sets CSP/`Referrer-Policy`/`X-Content-Type-Options` on both
browser-facing listeners (added this milestone -- see
`docs/threat-model.md`'s revision log for what this looked like before).
The production Docker image runs nonroot, and `deploy/stack.yml` adds
`read_only: true`, a scoped `tmpfs`, and `cap_drop: [ALL]` on top of
that.

**A06 Vulnerable and Outdated Components.** See the scan table above.
`docs/tested-versions.md` pins every component's exact version with a
citation for where it's pinned, so "what's actually running" is never a
guess.

**A07 Identification and Authentication Failures.** Admin
authentication delegates entirely to a mature OIDC library
(`coreos/go-oidc`) rather than hand-rolled JWT verification -- spec
section 9 explicitly requires this, and `internal/oidc/client_test.go`
verifies signature/issuer/audience/nonce checks against a real signing
provider, not a mock that just returns "valid." Session idle (30 min)
and absolute (8 hour) TTLs are both enforced (`internal/adminsession`),
and a stale/idle session is rejected even if its token hash still
matches a live row. No password exists anywhere in this system for
browsers or admins to have weak/reused/brute-forceable credentials --
the closest analog, the verification code shown on the waiting page, is
explicitly documented and enforced as non-authenticating (spec section
5): no public endpoint accepts it as a lookup key at all.

**A08 Software and Data Integrity Failures.** The Docker image is built
from a pinned base image by digest (`Dockerfile`), and CI runs from a
committed lockfile-equivalent (`go.sum`, `web/admin/package-lock.json`)
rather than floating version ranges. Audit-log integrity is enforced at
the database-role level, not just application code discipline (spec
section 11 control 10) -- `internal/store/roles_test.go` proves the
runtime role's `UPDATE`/`DELETE` on `audit_events` is rejected by
PostgreSQL itself, not merely unused by this codebase's current call
sites.

**A09 Security Logging and Monitoring Failures.** Every mutation writes
an audit event in the same transaction as the mutation itself (spec
section 12: "mutations fail if their audit event cannot commit"), and
`internal/metrics` (this milestone) exposes auth-decision counts/
latency, admin-action outcomes, rate-limit rejections, and audit-insert
failures for alerting. Structured logs are the standard library's
`log` package writing to stdout with service-relevant context; this
project has **not** implemented spec section 15's specific structured-
JSON-with-correlation-ID log format (see Gaps below) -- audit trail
completeness and metrics coverage are real, but "logs" in the
observability sense are still a plain-text gap.

**A10 Server-Side Request Forgery.** This service never fetches a
URL supplied by request input -- it explicitly never proxies or fetches
application content (spec section 1's core constraint), and the only
outbound HTTP calls it makes at all are to the *configured* (not
request-supplied) OIDC issuer for discovery/token exchange. There is no
code path where a browser- or admin-supplied string becomes part of an
outbound request's destination.

## Gaps found during this review (not previously tracked)

- **No structured JSON logging with correlation IDs** (spec section 15).
  Current logging is plain `log.Printf` to stdout. The audit trail
  (which is structured, DB-backed, and tested) covers the compliance/
  forensic need; this gap is specifically about operational log
  aggregation and per-request correlation across the four listeners.
- **No scheduled (cron) dependency/image scan in CI** -- both scans
  above were run manually for this review. Wiring `govulncheck` and
  `docker scout` into a scheduled GitHub Actions workflow would catch a
  newly-disclosed CVE against an unchanged dependency, which a
  push-triggered CI run never will.
- **The admin API's `Idempotency-Key` replay semantics are not
  implemented** (already noted in `docs/threat-model.md` section 6) --
  worth restating here specifically because a duplicate-request replay
  is the kind of thing a security review, not just a functional one,
  cares about (a network retry that resends a mutation with a network-
  level idempotency expectation the API doesn't actually provide).

None of these three block a release on their own -- each is a real,
specific, actionable gap rather than a vague "needs more security
work," which is the point of writing them down here instead of leaving
them implicit.
