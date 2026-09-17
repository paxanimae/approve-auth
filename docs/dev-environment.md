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

export DEV_NETWORK=traefik-manual-proxy_dev
export TEST_DATABASE_URL="postgres://postgres:devpassword@db:5432/manual_approval?sslmode=disable"
scripts/dev.sh test
```

`DEV_NETWORK` attaches the ephemeral Go test container to the same
Docker network as the `db` service so it can resolve the `db` hostname.
`TEST_DATABASE_URL` here is a superuser-capable connection string --
`internal/store`'s tests run migrations (including creating the
`manual_approval_app` / `manual_approval_maintenance` login roles) and
then connect as those specific roles to exercise the audit-immutability
grants from `migrations/000012_roles_and_grants.up.sql`.

Tests that share this database run with `-p 1` automatically (see
`scripts/dev.sh`): `internal/store`'s tests drop and recreate the whole
schema mid-run, which races against other packages' DB tests if Go runs
package test binaries concurrently.

## The two-host TLS test stack

Proves two independent HTTPS origins exist to build Milestone 2's
cookie-isolation tests against. It does **not** run the actual
`traefik-manual-proxy` service, and it never touches the Docker socket.

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

## Running the service itself locally

Not yet meaningful: Milestone 1 has no ForwardAuth logic, enrollment
flow, or admin console (see each `internal/*` package's `doc.go`). Once
those land, `cmd/server` will need `deploy/dev/certs`-style TLS material
for its own Authorization listener (distinct from the app-a/app-b certs
above, which are just test backends) -- see `internal/config`'s
`AUTH_TLS_CERT_FILE` / `AUTH_TLS_KEY_FILE` / `AUTH_CLIENT_CA_FILE`.
