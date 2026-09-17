# Traefik Manual Approval Authorization Service

Lets an administrator manually approve a browser (e.g. a reception TV) for
time-limited access to one Traefik-protected application hostname, via
ForwardAuth. Traefik remains the sole reverse proxy; this service owns
authorization decisions, approval requests, credentials, administration, and
audit history.

Status: **Milestones 1-5 substantially complete** (foundation, ForwardAuth +
Traefik integration, enrollment + lifecycle, the admin OIDC console, and
operations tooling). Milestone 6 (release hardening) is in progress. See
`docs/security-review.md` for a self-review pass and dependency/image scan
results, `docs/threat-model.md` for what's implemented vs. explicitly
deferred, and the sections below for how to actually run it.

## Start here

- **Operators deploying this for real:** `docs/runbooks/rollout-rollback.md`,
  then `docs/runbooks/key-rotation.md` and `docs/runbooks/backup-restore.md`
  before you need them under pressure.
- **Developers working on this repo:** `docs/dev-environment.md` for the
  containerized local setup (no Go/Node/mkcert install on the host), then
  the section below.
- **Understanding what this service does and doesn't do:** the product
  spec this build targets (not checked into this repo -- see whoever gave
  you this codebase for it) and `docs/threat-model.md`.
- **API contracts:** `api/public.yaml` and `api/admin.yaml` (OpenAPI 3.1,
  validated in CI against the real implementation, not a draft).

## Architecture at a glance

One binary (`cmd/server`) exposes four independently-routed listeners --
Public, Admin, Authorization (mTLS), and Operations -- backed by
PostgreSQL as the sole authoritative state store. `cmd/admin` is a separate
operator CLI (register applications, run migrations, revoke an admin
session urgently, purge the audit log) that talks to PostgreSQL directly,
never a network listener. See `docs/adr/` for why.

```
Browser -> Traefik HTTPS application router
              |
              +-> ForwardAuth -> Authorization listener -> PostgreSQL
              |
              +-> application backend (Traefik proxies all content)

Browser -> Traefik same-host /__manual-approval/* router -> Public listener
Admin   -> Traefik dedicated admin hostname -> Admin listener -> OIDC provider
Worker  -> PostgreSQL cleanup / audit expiry events (runs inside cmd/server)
```

## Development

No Go, Node, or mkcert install is required on the host. Every build/test/lint
command runs inside a pinned Docker image -- see `scripts/dev.sh` (bash) or
`scripts/dev.ps1` (PowerShell), and `docs/dev-environment.md` for the full
local setup including the real-Traefik integration stack and the admin
console's OIDC login flow against `cmd/mock-oidc`.

```bash
scripts/dev.sh build
scripts/dev.sh vet
scripts/dev.sh test
```

```powershell
scripts/dev.ps1 build
scripts/dev.ps1 vet
scripts/dev.ps1 test
```

Database-backed tests skip cleanly (`t.Skip`) without `TEST_DATABASE_URL`
set; see `docs/dev-environment.md` for running them against a real
PostgreSQL instance, and the real-Traefik integration suite.

## Repository layout

| Path | What's there |
|---|---|
| `cmd/server` | The one real service binary: all four listeners, the retention worker |
| `cmd/admin` | Operator CLI: register-application, migrate-up/-down, revoke-admin-session, purge-audit-log |
| `cmd/mock-oidc` | A real (not stubbed) OIDC provider for local dev/CI only -- never production |
| `internal/authz` | The ForwardAuth authoritative decision |
| `internal/enrollment` | Request/waiting/claim browser-facing flow |
| `internal/admin`, `internal/adminsession` | Admin mutation business logic; OIDC login + session |
| `internal/oidc` | The OIDC Authorization Code + PKCE client |
| `internal/store` | All PostgreSQL access; migrations live in `migrations/` |
| `internal/httpserver` | The four listeners' HTTP handlers |
| `internal/worker` | Retention/cleanup jobs (spec section 12) |
| `internal/metrics` | Prometheus metrics |
| `internal/config` | Config loading, secret handling, validation |
| `web/admin` | The Svelte admin console, embedded into the Go binary |
| `web/public` | Server-rendered, no-JS-capable request/waiting pages |
| `api/` | OpenAPI 3.1 contracts, validated in CI |
| `deploy/` | The Swarm deployment manifest (`stack.yml`) and its supporting files |
| `deploy/dev/` | The local dev/test stack (real Postgres, real Traefik, real mock OIDC) |
| `docs/` | Threat model, security review, dev environment, runbooks, ADRs |
