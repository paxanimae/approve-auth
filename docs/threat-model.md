# Threat model

Status: through Milestone 5. Documents the threat model from spec section
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
| CSRF against admin mutations | Same synchronizer-token approach, on the admin API; every mutation (including logout) requires an `X-CSRF-Token` header matching the session's own derived token | `internal/httpserver.requireAdminCSRF`, `internal/adminsession` (`csrfToken`/`validCSRFToken`) | **Implemented and tested** (`internal/httpserver/admin_handlers_test.go`'s missing/wrong-token cases; `internal/adminsession/service_test.go`'s logout CSRF cases) |
| Admin OIDC login itself: state/nonce/PKCE tampering, wrong audience, replayed authorization code | Backend Authorization Code + PKCE via `coreos/go-oidc` (a mature library, not custom JWT crypto); state/nonce/PKCE verifier stored server-side, single-use, 10-minute expiry; ID token nonce checked explicitly (go-oidc doesn't do this itself) | `internal/oidc.Client`, `internal/adminsession.Service.BeginLogin/HandleCallback`, `store.ConsumeOIDCTransaction` (atomic single-use) | **Implemented and tested** against a real (not mocked) RS256-signing OIDC provider (`internal/oidc/client_test.go`), and end to end against `cmd/mock-oidc` in the real dev stack (login redirect -> IdP -> callback -> session cookie -> authenticated API call) |
| Guessed request IDs / verification-code enumeration | Verification codes are a comparison aid only, never sufficient to retrieve a record; live-request uniqueness is DB-enforced | `migrations/000003` (partial unique index on live `verification_code`); every public lookup (`Status`, `Cancel`, `Claim`, `Ack`) resolves by pending-proof hash, never by verification code | **Implemented** -- the public endpoints never accept a verification code as a lookup key at all |
| Compromised low-privilege (`viewer`) admin account | Role check on every mutating call; `viewer` cannot mutate | `internal/httpserver.requireAdministrator`, `admin_sessions.role` CHECK constraint | **Implemented and tested** (`internal/httpserver/admin_handlers_test.go`'s `TestAdminMutation_ViewerRoleForbidden`) |
| Claim-retry envelope misuse (replaying/relinking an encrypted retry blob to the wrong request or credential) | AES-256-GCM with the request and application IDs as authenticated additional data -- ciphertext associated with the wrong row fails to decrypt | `internal/enrollment/envelope.go` | **Implemented and tested** (`internal/enrollment/service_test.go`'s retry and envelope-purged cases) |
| Missing CSP / clickjacking / MIME-sniffing on service-owned HTML pages | `Content-Security-Policy: default-src 'none'; script/style/img/font/connect-src 'self'; frame-ancestors 'none'; object-src 'none'`, `Referrer-Policy: same-origin` (spec section 11's literal text says `no-referrer`, but that value made the browser omit Referer even for this service's own same-origin enrollment-form submissions, breaking spec section 9's own "Origin absent -> same-origin Referer" fallback on any navigation path where Origin comes back empty/"null" -- found via real manual testing, not theoretical; `same-origin` still never leaks Referer cross-origin), `X-Content-Type-Options: nosniff` on every response from the Public and Admin listeners | `internal/httpserver.securityHeaders` | **Implemented and tested** (`internal/httpserver/security_headers_test.go`) |
| Unbounded enrollment bootstrap/status polling (resource exhaustion, faster verification-code guessing) | `bootstrap 30/minute per IP`, `status 20/minute per pending proof`, in addition to the existing `pending-request submissions 5/hour per application+client IP` | `internal/enrollment.Service.Bootstrap/Status` via `store.IncrementRateLimit` | **Implemented and tested** (`internal/enrollment/service_test.go`'s `TestBootstrap_RateLimitedPerIP`/`TestStatus_RateLimitedPerPendingProof`) -- this was a real gap: the config settings existed since Milestone 1 but nothing read them until Milestone 5 |
| A worker delay silently extending access past its true expiry | ForwardAuth's authoritative check derives allow/deny purely from live database timestamps on every request; the retention worker only marks terminal workflow state and writes audit events, never gates access itself | `internal/authz.Decide` (unchanged since Milestone 2); `internal/worker`/`internal/store/retention.go` | **Implemented and tested**, including a dedicated safety test proving a live authorization is never purged regardless of how old its request row is (`internal/store/retention_test.go`'s `TestPurgeResolvedRecords_NeverPurgesALiveAuthorization`) |
| Audit-log tampering via the retention/cleanup path itself | Audit-event purging (the one deletion the audit-immutability design permits at all) requires the separate `app_maintenance` role and runs only as a distinct one-shot operator command, never inside the always-running service process | `cmd/admin purge-audit-log`; migration 000012's grants | **Implemented and tested** (`internal/store/retention_test.go`'s `TestPurgeOldAuditEvents`, which explicitly connects as `manual_approval_maintenance`) |

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

- The admin API's `Idempotency-Key` replay semantics (spec section 9:
  store results 24 hours, replay returns the original result, conflicting
  bodies return 409) are not implemented -- mutations still use
  optimistic-concurrency `version` checks, which prevent a stale
  resubmission from silently succeeding twice, but a byte-for-byte
  identical retry after a lost response is not deduplicated and is not
  currently distinguishable from a fresh request.
- The dedicated "Expiring soon" console view (window/filter/sort
  controls, bulk renew/revoke from that specific view) is not built --
  `GET /api/v1/authorizations` already sorts soonest-expiring-first and
  the bulk-renew/bulk-revoke endpoints exist and are tested, but the
  minimal Svelte console's Sessions view doesn't yet expose the window
  presets, application/label/approver filters, or "renewable vs.
  credential-limit-reached" distinction spec section 10 describes.
- WCAG 2.2 AA has not been audited; the console's destructive-action
  confirmations use native `confirm()`/`prompt()` rather than accessible,
  focus-managed dialogs.
- Load testing against spec section 15's baseline targets (500 auth
  checks/second, 10,000 active authorizations, p95 <=50ms) has not been
  run -- it needs a real multi-replica deployment, not this single-
  container dev stack. See `docs/runbooks/load-testing.md`.
- A restore-from-backup drill has not been performed -- see
  `docs/runbooks/backup-restore.md` for the documented, not yet
  exercised, procedure.

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
- 2026-09-17 -- Milestone 4: real OIDC login (Authorization Code + PKCE)
  against a real signed-JWT provider, admin session CSRF/role
  enforcement, the full admin API (applications/requests/authorizations/
  audit-events, bulk actions), CSP/Referrer-Policy/X-Content-Type-Options
  on both browser-facing listeners, and a minimal functional Svelte
  console -- verified end to end against the real dev stack via
  `cmd/mock-oidc` (a real, not stubbed, OIDC provider for local dev).
  Fixed two real bugs found along the way: `GET /status`/`POST /requests`
  were marshaling Go structs with no `json` tags (PascalCase on the wire
  instead of spec's required snake_case), and the waiting page's
  JS-enhanced status polling (spec section 5 step 5) had never actually
  been implemented, only its no-JS `<meta refresh>` fallback.
- 2026-09-17 -- Milestone 5: the retention/cleanup worker (request
  timeout/claim-expiry transitions, idempotent authorization-expiry audit
  events, claim-envelope purge + pending-proof consumption, IP/user-agent/
  return-path redaction, resolved-record purging with a dedicated
  never-purge-a-live-authorization safety test, audit-log purging as a
  separate `app_maintenance`-role operator command), Postgres advisory-
  lock coordination across replicas, Prometheus metrics and `GET /readyz`
  on the Ops listener, and a Swarm deployment manifest. Fixed a real gap
  found while wiring rate-limit metrics: the bootstrap/status rate limits
  spec section 11 control 6 requires had config settings since Milestone
  1 but were never actually enforced.
- 2026-09-17 -- Dependency and image vulnerability scans (`govulncheck`
  against the module graph, `docker scout cves` against the built
  runtime image): zero known vulnerabilities in either as of this date.
  Re-run before release and periodically thereafter -- this is a
  point-in-time result, not a standing guarantee.
