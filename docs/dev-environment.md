# Local development environment

Everything runs in containers. The only things this machine needs are
**Docker** (with Compose) and **git** -- no Go, Node, or mkcert install.
See `docs/tested-versions.md` for the exact pinned image tags.

## Build, vet, test

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

Each command runs inside the pinned `golang` image, mounting the repo and
a persistent named Docker volume for the Go module cache (so repeated
runs don't re-download dependencies). A package path as the first
argument replaces the default `./...`, e.g. `scripts/dev.sh test
./internal/store/...`.

## Running tests against real PostgreSQL

Some tests (`internal/store`, `internal/audit`) need a real database and
`t.Skip` cleanly when one isn't configured. To run them:

```bash
docker compose -f deploy/dev/docker-compose.yml up -d db

export DEV_NETWORK=approve-auth_dev
export TEST_DATABASE_URL="postgres://postgres:devpassword@db:5432/approve_auth?sslmode=disable"
scripts/dev.sh test
```

`DEV_NETWORK` attaches the ephemeral Go test container to the same
Docker network as the `db` service so it can resolve the `db` hostname.
`TEST_DATABASE_URL` here is a superuser-capable connection string --
`internal/store`'s tests run migrations (including creating the
`approve_auth_app` / `approve_auth_maintenance` login roles) and
then connect as those specific roles to exercise the audit-immutability
grants from `migrations/000012_roles_and_grants.up.sql`.

Tests that share this database run with `-p 1` automatically (see
`scripts/dev.sh`): `internal/store`'s tests drop and recreate the whole
schema mid-run, which races against other packages' DB tests if Go runs
package test binaries concurrently.

## The two-host TLS test stack

Proves two independent HTTPS origins exist to build Milestone 2's
cookie-isolation tests against. It does **not** run the actual
`approve-auth` service, and it never touches the Docker socket.

1. Generate self-signed dev certs (containerized, nothing installed or
   trusted on this machine):

   ```bash
   scripts/gen-certs.sh
   ```

   This is **not mkcert**: mkcert's whole point is installing a
   locally-trusted CA into your OS/browser trust store, which is a
   host-side change we deliberately avoid here. Browsers will show a
   certificate warning when visiting these hosts -- that's expected. If
   you want the no-warning experience, install mkcert yourself and trust
   `deploy/dev/certs/` -- that's your call, not something these scripts
   do for you.

2. Bring up the two hosts:

   ```bash
   docker compose -f deploy/dev/docker-compose.yml up -d app-a app-b
   ```

3. Browse `https://app-a.localtest.me:10443/` and
   `https://app-b.localtest.me:10444/`. `*.localtest.me` is a public DNS
   name that resolves to `127.0.0.1`, so this should work with no
   `/etc/hosts` edits. Confirm: a certificate warning (expected --
   self-signed), distinct placeholder text per host, and (via browser
   devtools) that a cookie set on `app-a.localtest.me` is never sent to
   `app-b.localtest.me`.

   **If `*.localtest.me` doesn't resolve** (some networks/sandboxes block
   arbitrary public DNS lookups -- this happened in the environment this
   milestone was built in), add these lines to your hosts file instead
   (`/etc/hosts` on Linux/macOS, `C:\Windows\System32\drivers\etc\hosts`
   on Windows, admin rights required) and browse the same URLs:

   ```
   127.0.0.1 app-a.localtest.me
   127.0.0.1 app-b.localtest.me
   ```

Ports `10443`/`10444` are deliberately outside the real service's own
port range (8080/8081/8443/9090 -- see `internal/config`'s
`PUBLIC_ADDR`/`ADMIN_ADDR`/`AUTH_ADDR`/`OPS_ADDR`), so there's no
confusion between "fake test hosts" and "the actual service."

## Running the real-Traefik integration stack

Milestone 2 added a real ForwardAuth decision, so this now runs the
actual service, a real Traefik, and a placeholder backend together.
`tests/integration/traefik_test.go` exercises this stack -- mock-only
tests can't verify real routing/cookie behavior (spec section 16).

1. Generate certs (both scripts; the mTLS ones are new for this stack):

   ```bash
   scripts/gen-certs.sh
   scripts/gen-mtls-certs.sh
   ```

2. Bring up the stack (`--build` picks up any source change; `migrate`
   is one-shot and applies migrations with a privileged connection --
   spec section 13 -- before `approve-auth` starts, which connects
   with its own least-privilege runtime role):

   ```bash
   docker compose -f deploy/dev/docker-compose.yml up -d --build \
     migrate approve-auth backend-protected traefik
   ```

3. Run the integration tests. Like the Postgres-backed tests, these
   `t.Skip` cleanly when unconfigured:

   ```bash
   export DEV_NETWORK=approve-auth_dev
   export TEST_DATABASE_URL="postgres://postgres:devpassword@db:5432/approve_auth?sslmode=disable"
   export TRAEFIK_ADDR="traefik:443"
   scripts/dev.sh test ./tests/integration/...
   ```

   `TRAEFIK_ADDR` uses the internal service name/port (not the
   host-published `18443`) because the Go test itself runs inside a
   container on the same Docker network -- see `newTraefikClient` in
   that file for how it dials this address while still sending
   `protected.localtest.me` as the Host/SNI.

   Don't run `internal/store`'s tests (which drop and recreate the whole
   schema, e.g. plain `scripts/dev.sh test` with no package path) against
   the same database while `approve-auth` is left running against it:
   its connection pool ends up with stale state from the schema churn and
   every query starts failing closed (503) until it's restarted --
   `docker compose -f deploy/dev/docker-compose.yml restart
   approve-auth` fixes it. This can't happen in CI, where each job
   gets a fresh database and a freshly-started service with no such
   churn in between.

4. To poke at it manually instead, from the host: Traefik's edge is
   published at `127.0.0.1:18443`. `protected.localtest.me` isn't
   registered as an application until a test (or
   `admin register-application`) creates it, so an unregistered request
   gets a generic 403 first. Example, once registered:

   ```bash
   curl -sk -D - --resolve protected.localtest.me:18443:127.0.0.1 \
     -H "Host: protected.localtest.me" \
     https://protected.localtest.me:18443/dashboard
   ```

   The explicit `Host` header matters here specifically because `18443`
   is a non-standard port for local testing -- a browser or curl
   connecting to the real port 443 wouldn't include a port in the Host
   header at all, and hostnames are registered without one (spec section
   3 rejects non-443 ports at registration time).

5. To try the admin console itself, bring up `mock-oidc` too (a real,
   minimal OIDC provider -- see `cmd/mock-oidc`'s doc comment -- that
   auto-approves every login as one hardcoded `grp-admins` identity; it
   is never a production component):

   ```bash
   docker compose -f deploy/dev/docker-compose.yml up -d --build \
     migrate approve-auth mock-oidc backend-protected traefik
   ```

   Then, from the host browser: `https://admin.localtest.me:18443/`,
   click "Log in" (accept the self-signed-cert warning, same as the
   other `*.localtest.me` hosts). `deploy/dev/approve-auth-config.yaml`
   already points `oidc_issuer`/`admin_origin` at this stack's addresses.
   If plain DNS resolution of `*.localtest.me` isn't available in your
   environment, use the same `curl --resolve` trick as step 4 above --
   `admin.localtest.me` needs it for both `/` and `/auth/callback`, and
   `mock-oidc.localtest.me` for the redirect in between.

Notes on what's dev-only in this stack, not something a real deployment
does: `approve-auth`'s compose service overrides to `user: "0:0"`
because Docker Desktop's Windows bind-mount layer doesn't reliably
preserve the permissions the image's nonroot user needs to read
`/mtls/*` -- a Swarm deployment uses secrets/volumes instead of a host
bind mount and doesn't hit this. `backend-protected` speaks plain HTTP
to Traefik (not HTTPS): every TLS variant tried on that hop hit an
identical "tls: internal error" specific to this environment (see
`deploy/dev/Caddyfile.protected`'s comment) that's unrelated to what
this milestone verifies -- the browser-facing edge (Traefik's own
`websecure` entry point) is still real HTTPS, which is what actually
matters here. `mock-oidc` (see step 5) exists only because this dev
stack has no real organizational identity provider to test the admin
console's OIDC login against; `admin_origin` includes `:18443` for the
same non-standard-port reason `docs/dev-environment.md`'s curl example
above needs an explicit `Host` header -- a real deployment's admin
hostname has no port, since Traefik only ever publishes 443.

## The two-host TLS test stack

This one is unrelated to the real-Traefik stack above -- it predates
ForwardAuth logic existing at all, and just proves two independent HTTPS
origins exist to build cookie-isolation tests against. It does not run
the actual `approve-auth` service.
