# Load testing

Status: baseline and script written against spec section 15's targets.
**Not yet run against a real multi-replica deployment** -- this repo's
dev stack is a single-container, single-node setup meant for
correctness testing, not performance measurement, and running a load
test against it would measure this laptop/CI runner, not the
architecture spec section 15 actually asks about.

## Baseline acceptance target (spec section 15)

- 500 auth checks/second for 15 minutes sustained.
- 1,000 concurrent waiting browsers (polling `GET /status`).
- 10,000 active authorizations already seeded in the database.
- Two `manual-approval` replicas at 2 vCPU / 512 MiB each (matches
  `deploy/stack.yml`'s `resources.limits`), PostgreSQL at 2 vCPU / 2 GiB,
  same regional network.
- Targets: auth p95 <=50ms, p99 <=150ms (excluding internet latency),
  <0.1% unexpected errors, stable memory, zero unauthorized allows.

## What to actually measure

`internal/metrics` (Milestone 5) already exposes the two metrics this
test cares about most directly on the Ops listener's `GET /metrics`:

- `manual_approval_auth_decision_duration_seconds` -- a histogram; the
  p95/p99 targets above are `histogram_quantile(0.95, ...)` /
  `histogram_quantile(0.99, ...)` over this during the run.
- `manual_approval_auth_decisions_total{category="allow"}` vs. every
  other category/`error` -- "zero unauthorized allows" means watching
  for any `allow` decision your synthetic data didn't actually expect,
  not just an aggregate error rate.

Scrape `/metrics` from a Prometheus instance pointed at the test
environment for the duration of the run rather than only reading the
load-generator's own client-side numbers -- client-side latency
includes network hops the server-side histogram doesn't, and the two
should be compared, not conflated.

## Seeding 10,000 active authorizations

Don't do this through the real enrollment flow (it would take far
longer than the test itself and isn't what's being measured here) --
seed directly via SQL against a disposable test database, mirroring
what `internal/store`'s own test fixtures already construct by hand
(see `internal/store/testutil_test.go`'s `insertApplication`/
`insertAuthorization`/`insertCredential` for the exact shape a valid
row needs): one test application, 10,000 authorizations with
`activated_at` set, `expires_at` comfortably in the future, and a
matching `credentials` row each holding a real 32-byte token hash whose
*raw* token the load generator actually presents as the
`__Host-manual-proxy` cookie value on its synthetic `/auth` requests.

## Generating the auth-check load

`GET /auth` needs the same forwarded-header shape Traefik sends (spec
section 6) -- a raw load generator has to set these itself, it isn't
naturally produced by a generic HTTP load tool pointed at the URL. A
`vegeta` (or `k6`) target list works well here since each target line
can carry its own headers/cookie:

```
GET https://manual-approval-under-test:8443/auth
X-Forwarded-Host: loadtest-app.example.test
X-Forwarded-Proto: https
X-Forwarded-Method: GET
X-Forwarded-Uri: /dashboard
Cookie: __Host-manual-proxy=<one of the 10,000 seeded raw tokens>
```

Generate one such target per seeded authorization (or cycle through a
smaller pool if 10,000 distinct connections is impractical for the load
tool itself) and run through `vegeta attack -rate=500/s -duration=15m
-targets=... -cert=... -key=... -root-certs=...` (mTLS client
credentials, matching what Traefik itself would present) piped to
`vegeta report`.

## Generating the concurrent-poller load

1,000 concurrent "waiting browsers" means 1,000 long-lived clients each
polling `GET /__manual-approval/status` on the real cadence
`web/public/assets/app.js` actually implements (5s+jitter, per spec
section 5 step 5) -- not 1,000 requests fired as fast as possible. A
small script driving 1,000 goroutines/workers, each sleeping
`jitter(5s, 1s)` between requests against a pending (never-approved)
test request's cookie, models this more faithfully than a generic
constant-rate attack tool.

## Results log

*(Empty. Fill in after the first real run against a real multi-replica
environment: date, environment description, actual p95/p99, error rate,
memory behavior over the 15 minutes, and whether every target was met.
An unrun load test proves nothing about spec section 15's targets --
this section existing empty is the honest state of that today.)*
