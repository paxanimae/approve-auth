# Traefik Manual Approval Authorization Service

Lets an administrator manually approve a browser (e.g. a reception TV) for
time-limited access to one Traefik-protected application hostname, via
ForwardAuth. Traefik remains the sole reverse proxy; this service owns
authorization decisions, approval requests, credentials, administration, and
audit history. See `docs/` for the full specification, threat model, and
tested-versions matrix this build targets.

Currently at **Milestone 1: Foundation and contracts** — repository scaffold,
schema/migrations, config validation, OpenAPI drafts, threat model, and a
local two-host TLS test stack. No business logic (ForwardAuth allow/deny,
enrollment flow, admin console, OIDC) is implemented yet; see `docs/adr/`
and package `doc.go` comments for what's stubbed vs. real.

## Development

No Go, Node, or mkcert install is required on the host. Every build/test/lint
command runs inside a pinned Docker image — see `scripts/dev.sh` (bash) or
`scripts/dev.ps1` (PowerShell), and `docs/dev-environment.md` for the full
local setup including the two-host TLS stack.

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
