# Threat model

Status: Milestone 1 draft. Documents the threat model from spec section
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
| Forged `X-Forwarded-Host`/`-Proto`/`-For` from an untrusted caller | `/auth` only accepts calls from an mTLS-authenticated, allowlisted Traefik client identity; entry points must set `forwardedHeaders.insecure=false` with explicit `trustedIPs` | `internal/httpserver.AuthTLSConfig` (client cert + `VerifyPeerCertificate` against `AUTH_ALLOWED_CLIENT_IDENTITIES`); Traefik config (operator-owned, documented in `docs/dev-environment.md`/deploy docs) | **Implemented** (mTLS + identity allowlist); the Traefik-side entry-point config is a deployment requirement, not something this service can enforce from inside |
| Routing bypass / control-plane endpoints reachable from the wrong listener | Four independently-routed `http.ServeMux` instances, not path guards on one mux | `internal/httpserver` | **Implemented and tested** (`httpserver_test.go`, `integration_test.go`) |
| Copied/stolen bearer cookie used on the wrong application | Composite FK chain (`credential -> authorization -> request`) so the database itself rejects a credential whose `application_id` doesn't match its authorization's | `migrations/000004`, `000005` | **Implemented and tested** (`internal/store/constraints_test.go`) |
| Approval races (approve vs. deny, renew vs. revoke, claim vs. disable) | Row locks + optimistic `version` columns; transactional mutation+audit commits | Schema has `version` columns on every mutable table now; the actual locking logic is Milestone 3 | **Schema ready, logic deferred to Milestone 3** |
| Tampering with the audit trail after the fact | Two-role grant design: the runtime role can `INSERT` but never `UPDATE`/`DELETE` `audit_events`; only a separate maintenance role (used solely by retention jobs) can delete | `migrations/000012_roles_and_grants.up.sql` | **Implemented and tested** (`internal/store/roles_test.go`, `internal/audit/postgres_test.go`) |
| Secrets leaking via env vars, logs, or image layers | Secrets read only from `<NAME>_FILE` paths; the bare env var being set at all (any value) is a hard startup error | `internal/config.loadSecrets` | **Implemented and tested** (`internal/config/config_test.go`) |
| Malformed/missing security configuration reaching a running listener | `Validate()` aggregates every configuration problem and `cmd/server` refuses to bind any listener if it returns an error | `internal/config.Validate`, `cmd/server/main.go` | **Implemented** |
| CSRF against enrollment/admin mutations | Synchronizer CSRF tokens, exact-Origin checks | `internal/enrollment`, `internal/admin` (Milestone 2/3) | **Deferred to Milestone 2/3** -- no mutation logic exists yet to protect |
| Guessed request IDs / verification-code enumeration | Verification codes are a comparison aid only, never sufficient to retrieve a record; live-request uniqueness is DB-enforced | `migrations/000003` (partial unique index on live `verification_code`); lookup-by-code-alone is never implemented | **Schema control implemented**; the "no lookup by code alone" property holds vacuously today (no lookup endpoints exist yet) and must be preserved when Milestone 2 adds them |
| Compromised low-privilege (`viewer`) admin account | Role check on every mutating call; `viewer` cannot mutate | `internal/admin` (Milestone 3/4); `admin_sessions.role` CHECK constraint exists now | **Schema control implemented, enforcement deferred to Milestone 3/4** |

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

## 6. Explicit non-goals for Milestone 1

No ForwardAuth allow/deny decision, no enrollment flow, no admin
authentication/authorization enforcement, no rate limiting, no CSRF
protection (nothing mutates state from an untrusted caller yet), and no
retention/cleanup worker. These are Milestones 2 through 5; this
document will grow a row in the table above as each lands.

## 7. Revision log

- 2026-09-17 -- Initial draft, covering Milestone 1's actual controls
  (listener separation, composite-FK application consistency, audit
  immutability roles, config secret handling, mTLS + client-identity
  allowlist).
