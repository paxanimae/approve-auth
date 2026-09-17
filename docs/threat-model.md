# Threat model

Status: through Milestone 3. Documents the threat model from spec section
11 and which control is enforced by which layer today versus a later
milestone. This is a living document -- update it as each milestone lands
its controls, not just once at the end.

## 1. Purpose and scope

This service makes one kind of decision: whether a specific browser may
reach a specific protected application hostname, for a limited time,
after an administrator approved it. It does not proxy application
content, does not manage application-level permissions (Grafana roles,
datasource access, etc.), and does not attempt to defend against a fully
compromised backend, database, or Swarm host -- see section 6.

## 2. Trust boundaries

| Boundary | Trusted for | Not trusted for |
|---|---|---|
| Traefik | Forwarding metadata (`X-Forwarded-*`) once mTLS-authenticated on the Authorization listener; routing reserved paths correctly | Anything if its own entry-point config trusts arbitrary internet `X-Forwarded-*` values -- that's a Traefik-side misconfiguration this service cannot detect |
| PostgreSQL | Sole authoritative state; the two-role grant design (below) | Being tamper-proof against a Swarm/DB administrator -- see section 6 |
| Administrators | Approve/deny/renew/revoke decisions within their role (viewer vs. administrator) | Bypassing CSRF/role checks -- those are enforced regardless of who's asking |
| Application backends | Receiving the access cookie (it has `Path=/`, so it reaches them) | Being trusted with that cookie's secrecy -- section 4 assumes backends are inside the trust boundary but does not assume they're free of XSS/CSRF themselves |
| Swarm operators | Deploying/operating the stack | Nothing beyond that -- an operator with host/DB access can always see or alter data; this is out of scope, not a gap |

## 3. Actors and assets

- **Actors:** anonymous internet clients, browsers with a valid credential, administrators (viewer/administrator roles), Traefik itself, application backends, the retention/cleanup worker (Milestone 5).
- **Assets:** the `applications` registry, pending/approved requests, authorizations and their credentials, admin sessions, and the audit log. The audit log is itself an asset (integrity, not just confidentiality).

## 4. Threats and controls

| Threat | Control | Enforcement layer | Status |
|---|---|---|---|
| Forged `X-Forwarded-Host`/`-Proto`/`-For` from an untrusted caller | `/auth` only accepts calls from an mTLS-authenticated, allowlisted Traefik client identity; entry points must set `forwardedHeaders.insecure=false` with explicit `trustedIPs` | `internal/httpserver.AuthTLSConfig` (client cert + `VerifyPeerCertificate` against `AUTH_ALLOWED_CLIENT_IDENTITIES`); `internal/httpserver.parseAuthRequest` requires a single, well-formed `X-Forwarded-Host`/`-Proto`/`-Method`/`-Uri` or returns 400; Traefik config (operator-owned) | **Implemented and tested against real Traefik** (`tests/integration/traefik_test.go`); the Traefik-side entry-point `trustedIPs` config is a deployment requirement this service cannot enforce from inside |
| ForwardAuth allow/deny decision itself: wrong host, disabled app, missing/expired/revoked/cross-application credential | The authoritative check (spec section 3), evaluated against one consistent DB read | `internal/authz.Decide`, `internal/store.GetAccessSnapshot` | **Implemented and tested**, both as a fake-store unit-test matrix (`internal/authz/service_test.go`) and end-to-end through real Traefik + a real backend (`tests/integration/traefik_test.go`) |
| Total service/DB outage silently bypassing approval | A `Decide` error (DB down, decision timeout) is a 503 from `/auth`, which Traefik's ForwardAuth middleware turns into a hard failure -- never a proxied backend request | `internal/httpserver.authHandler`; Traefik's own ForwardAuth behavior on an unreachable auth server | **Implemented**; verified manually against the real stack (stopping the service mid-test returned 500 from Traefik, never the backend's content) -- not automated as a repeatable test since it requires taking down a shared dev stack, see the comment in `tests/integration/traefik_test.go` |
| Routing bypass / control-plane endpoints reachable from the wrong listener | Four independently-routed `http.ServeMux` instances, not path guards on one mux | `internal/httpserver` | **Implemented and tested** (`httpserver_test.go`, `integration_test.go`) |
| Copied/stolen bearer cookie used on the wrong application | Composite FK chain (`credential -> authorization -> request`) so the database itself rejects a credential whose `application_id` doesn't match its authorization's | `migrations/000004`, `000005` | **Implemented and tested** (`internal/store/constraints_test.go`) |
| Approval races (approve vs. deny, renew vs. revoke, claim vs. disable, concurrent claim) | Row locks (`FOR UPDATE`) + optimistic `version` columns; transactional mutation+audit commits | `internal/store`'s Approve/Deny/Revoke/Renew/ClaimApproved | **Implemented and tested**, both sequentially (stale-version conflicts in `lifecycle_test.go`, `internal/admin`'s own tests) and under genuine concurrency (`internal/store/race_test.go`: 8 goroutines racing `ClaimApproved` produce exactly one credential) |
| Tampering with the audit trail after the fact | Two-role grant design: the runtime role can `INSERT` but never `UPDATE`/`DELETE` `audit_events`; only a separate maintenance role (used solely by retention jobs) can delete | `migrations/000012_roles_and_grants.up.sql`; every mutation writes its audit row in the same transaction (`internal/store/audit_insert.go`) | **Implemented and tested** (`internal/store/roles_test.go`, `internal/audit/postgres_test.go`, `internal/store/audit_insert_test.go`) |
| Secrets leaking via env vars, logs, or image layers | Secrets read only from `<NAME>_FILE` paths; the bare env var being set at all (any value) is a hard startup error | `internal/config.loadSecrets` | **Implemented and tested** (`internal/config/config_test.go`) |
| Malformed/missing security configuration reaching a running listener | `Validate()` aggregates every configuration problem and `cmd/server` refuses to bind any listener if it returns an error | `internal/config.Validate`, `cmd/server/main.go` | **Implemented** |
| CSRF against enrollment mutations | Synchronizer CSRF tokens (HMAC of the enrollment context's stored secret) on requests/cancel/claim/ack; exact-Origin-or-same-origin-Referer required on every mutating public endpoint | `internal/enrollment` (`csrf.go`), `internal/httpserver.checkOrigin` | **Implemented and tested**, including end-to-end against real Traefik (`tests/integration/enrollment_flow_test.go`) -- which is what caught `Status` not actually carrying the CSRF token the waiting page's forms needed, before this line could honestly say "implemented" |
| CSRF against admin mutations | Same synchronizer-token approach, on the admin API | Deferred to Milestone 4 -- `internal/admin`'s business logic exists and is tested, but no HTTP endpoint or admin session exists yet to attach CSRF protection to | **Deferred to Milestone 4** |
| Guessed request IDs / verification-code enumeration | Verification codes are a comparison aid only, never sufficient to retrieve a record; live-request uniqueness is DB-enforced | `migrations/000003` (partial unique index on live `verification_code`); every public lookup (`Status`, `Cancel`, `Claim`, `Ack`) resolves by pending-proof hash, never by verification code | **Implemented** -- the public endpoints never accept a verification code as a lookup key at all |
| Compromised low-privilege (`viewer`) admin account | Role check on every mutating call; `viewer` cannot mutate | `internal/admin` (Milestone 4 for the actual HTTP enforcement); `admin_sessions.role` CHECK constraint exists now | **Schema control implemented, HTTP-level enforcement deferred to Milestone 4** |
| Claim-retry envelope misuse (replaying/relinking an encrypted retry blob to the wrong request or credential) | AES-256-GCM with the request and application IDs as authenticated additional data -- ciphertext associated with the wrong row fails to decrypt | `internal/enrollment/envelope.go` | **Implemented and tested** (`internal/enrollment/service_test.go`'s retry and envelope-purged cases) |

## 5. Residual risks (by design, not gaps)

- A full compromise of the backend, database, or a Swarm host is out of
  scope for *prevention* -- the goal is to minimize damage (audit
  immutability, no plaintext secrets at rest) rather than pretend it
  can't happen.
- Possession of a stolen valid bearer cookie grants access on its
  approved host until expiration/revocation. There is no hardware-bound
  device identity in v1.
- An already-open WebSocket/SSE/streaming connection cannot be
  terminated by a later revocation; only the next handshake is gated.
- HttpOnly prevents ordinary script reads of the cookie, not same-origin
  script-initiated requests -- applications are still responsible for
  their own XSS/CSRF defenses.

## 6. Explicit non-goals so far

No admin authentication/authorization enforcement (no OIDC, no admin
session, no HTTP endpoint on the admin listener beyond a 501 stub) and
no retention/cleanup worker (timed-out/claim-expired requests reach
those states in the schema but nothing sweeps for them yet). These are
Milestones 4 and 5; this document will grow a row in the table above as
each lands.

## 7. Revision log

- 2026-09-17 -- Initial draft, covering Milestone 1's actual controls
  (listener separation, composite-FK application consistency, audit
  immutability roles, config secret handling, mTLS + client-identity
  allowlist).
- 2026-09-17 -- Milestone 2: the ForwardAuth allow/deny decision itself
  is implemented and verified against a real Traefik instance, a real
  backend, and real database state (not mocks) -- see
  `tests/integration/traefik_test.go`.
- 2026-09-17 -- Milestone 3: the enrollment flow (request/status/cancel/
  claim/ack/logout/session), CSRF protection, claim-retry envelope
  encryption, and admin approve/deny/renew/revoke business logic are all
  implemented and tested, including a full real-Traefik end-to-end run
  (`tests/integration/enrollment_flow_test.go`) and a genuine-concurrency
  race test (`internal/store/race_test.go`).
