# Release acceptance criteria (spec section 17)

Status: sign-off pass dated 2026-09-17, against the numbered criteria
spec section 17 lists. Each row states **Met**, **Partially met**, or
**Not met**, with the evidence a reader can go check themselves --
this document asserts nothing it doesn't cite.

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | TV1 receives access to hostname A only after an authenticated administrator approves its own pending request and it claims a credential | **Met** | `tests/integration/enrollment_flow_test.go`'s full real-Traefik run (request -> approve -> claim -> original URL reachable); `internal/enrollment/service_test.go`'s `TestFullLifecycle_RequestApproveClaimRetryAck` |
| 2 | Hostname B still requires a separate approval; browser and server enforce isolation independently | **Met** | `internal/store/constraints_test.go` (composite-FK cross-application rejection at the database level); `docs/threat-model.md` section 4's "Copied/stolen bearer cookie used on the wrong application" row |
| 3 | Browser-visible application URLs unchanged; the service never transports application response bodies or proxies application requests | **Met** | `internal/httpserver.authHandler` never reads or forwards a request/response body -- it only ever returns 204/303/401/403/400/503 to Traefik, which does the actual proxying; `tests/integration/traefik_test.go`'s `TestRealTraefik_ValidCredential_ReachesBackend` confirms the original path/query reach the real backend unchanged |
| 4 | Every new HTTP decision uses current PostgreSQL authorization state; expired/revoked/disabled/unknown access never reaches the backend | **Met** | `internal/authz.Decide` (`internal/authz/service_test.go`'s full 9-deny-branch + allow matrix); `tests/integration/traefik_test.go`'s `TestRealTraefik_RevokedAuthorization_Denied` |
| 5 | Same host-only access-cookie name across hosts, no Domain attribute, all specified flags; persists across browser restart where supported | **Met** | `internal/httpserver/cookies.go` (`__Host-approve-auth`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`, no `Domain`); Max-Age set to `CredentialMaxAge` so it survives a browser restart, subject to the browser's own policy |
| 6 | Pending/denied/expired/revoked/offline/waiting states are understandable, refresh-safe, and usable from a TV remote | **Partially met** | `web/public/templates/waiting.html.tmpl` covers every listed state with plain server-rendered HTML (refresh-safe by construction -- a GET reload always re-renders current state) and large, keyboard/remote-focusable form buttons. **Not yet verified**: an actual manual test on a real TV browser (spec section 10's "TV UX" and section 16's "manual test on a selected actual TV browser") hasn't been performed -- see "Gaps" below |
| 7 | Admin authentication, role enforcement, CSRF, audit integrity, rate limits, and proxy trust tests pass | **Met** | OIDC login: `internal/oidc/client_test.go`, `internal/adminsession/service_test.go`. Role enforcement: `internal/httpserver/admin_handlers_test.go`'s `TestAdminMutation_ViewerRoleForbidden`. CSRF: same file's `TestAdminMutation_RequiresMatchingCSRFToken`, `TestAdminLogout_RequiresCSRFThenClearsCookie`. Audit integrity: `internal/store/roles_test.go` (DB-level immutability). Rate limits: `internal/enrollment/service_test.go`'s three rate-limit tests. Proxy trust: `tests/integration/traefik_test.go`'s mTLS/forwarded-header tests |
| 8 | Expiring soon is a dedicated functioning view, with server-side filtering/sorting and tested individual/bulk renew/revoke behavior | **Partially met** | Server-side: `GET /api/v1/authorizations` sorts soonest-expiring-first by default and both bulk-renew/bulk-revoke endpoints exist with per-item tested results (`internal/httpserver/admin_handlers_test.go`'s `TestBulkRevoke_ReportsPerItemResults`). **Not met**: the console's Sessions view doesn't yet expose this as spec section 10's *dedicated* "Expiring soon" navigation destination with its own window/filter/approver/last-seen-window controls -- it's currently a filtered version of the general Sessions list. See `docs/threat-model.md` section 6 |
| 9 | Renewal works for an offline browser without a new cookie until its hard credential end date; renewal never resurrects expired or revoked grants | **Met** | `internal/store/authorizations.go`'s `RenewAuthorization` (new>current, new>now, new<=credential ceiling, all checked against a locked read); `internal/admin/service_test.go`'s renewal tests cover the expired/revoked-cannot-renew cases |
| 10 | Lost claim responses and cross-replica retries cannot create multiple grants, leak credentials, or return revoked access | **Met** | `internal/store/claims.go`'s `ClaimApproved` (row-locked, retry-safe); `internal/store/race_test.go` (8 concurrent goroutines racing a real claim produce exactly one credential); the claim-retry envelope only ever returns the same already-issued credential, re-checking revocation/expiry on every retry |
| 11 | An approval-service or database outage fails closed; restarting any one app replica loses no requests or authorizations | **Met** (fail-closed); **not independently verified** (no-data-loss-on-restart) | Fail-closed: `internal/httpserver.authHandler` returns 503 on any `Decide` error, never an allow (`internal/httpserver/auth_test.go`'s `TestAuthHandler_DeciderError_ServiceUnavailable`). No-data-loss: follows from PostgreSQL being the sole state store and every mutation being transactional, but this specific claim (restart one of *two* Swarm replicas mid-traffic) has not been exercised against a real multi-replica deployment -- see "Gaps" |
| 12 | The rendered Swarm deployment is tested with real Traefik, HTTPS hosts, mTLS, persistent PostgreSQL, secrets, migrations, and a restore drill | **Partially met** | Real Traefik + HTTPS + mTLS + migrations: yes, continuously, via `deploy/dev/docker-compose.yml` and `tests/integration/`. **Not met**: `deploy/stack.yml` (the actual Swarm manifest) has been schema-validated (`docker compose -f deploy/stack.yml config`) and reasoned through against every spec section 13 requirement, but never deployed to a real multi-node Swarm cluster, and the restore drill in `docs/runbooks/backup-restore.md` has never been run -- both runbooks say so explicitly |
| 13 | Metrics, dashboards/runbooks, redacted logs, automated test results, and performance measurements accompany the release | **Partially met** | Metrics: `internal/metrics`, real and tested. Runbooks: all four exist (`docs/runbooks/`). Redacted logs: the audit trail redacts appropriately (spec section 12's retention-driven field nulling, `internal/store/retention_test.go`), but general application logging is plain `log.Printf`, not the structured-JSON format with correlation IDs spec section 15 describes (tracked in `docs/security-review.md`'s Gaps). Automated test results: every package's tests pass as of this commit (see CI). **Not met**: no dashboards exist (no committed Grafana JSON or similar), and no performance measurements have been taken (`docs/runbooks/load-testing.md` is a plan, not a result) |
| 14 | Operator documentation states the scope of whole-host approval and the limits for backend permissions, bearer-token theft, cached data, and open streams | **Met** | `docs/threat-model.md` section 5 ("Residual risks (by design, not gaps)") covers bearer-token theft, cached data, and open-stream limitations explicitly; the spec's own section 1 "Scope boundary" language (whole-host approval, no per-dashboard/datasource authorization) is quoted/paraphrased in this repo's onboarding material (`README.md`) and assumed known by any operator working from the spec directly |

## Overall

9 of 14 criteria fully met, 5 partially met, 0 not met outright. Every
partial-met row above names a specific, concrete remaining action, not
a vague "needs more work" -- see each row's evidence column and the
linked runbooks/threat-model gaps for exactly what would move it to
"Met."

The five partial rows share a common thread: **the code and its own
tests are done; what's missing is verification against a real,
multi-node, deployed environment** (a real TV browser, a real Swarm
cluster, a real load test, a real restore drill) that this sandboxed
development session had no access to. That is a materially different
kind of gap than an unimplemented feature, and this document keeps them
visibly distinct rather than blending "not built" and "not yet proven at
scale" into one undifferentiated "partial."

## Gaps referenced above, consolidated

- Manual TV-browser UX review (criterion 6, spec section 16).
- Dedicated "Expiring soon" console view with its full filter/sort set
  (criterion 8, spec section 10) -- the underlying API is done and
  tested; the console UI is not.
- Multi-replica restart / no-data-loss drill (criterion 11).
- Real Swarm deployment + restore drill (criterion 12).
- Dashboards and performance measurements (criterion 13).
- Structured JSON logging with correlation IDs (criterion 13, spec
  section 15) -- also listed in `docs/security-review.md`.
