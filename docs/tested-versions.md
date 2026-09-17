# Tested versions

Every version below was resolved and verified working during Milestone 1
(2026-09-17), inside containers -- nothing is installed on the
development machine itself (see `docs/dev-environment.md`). Pin updates
should re-verify each row, not assume history.

| Component | Version | Where pinned | Notes |
|---|---|---|---|
| Go | 1.25.14 | `scripts/dev.sh`/`dev.ps1` (`golang:1.25.14` image), `.go-version`, `.github/workflows/ci.yml` | `go.mod`'s `go 1.25.11` line is golang-migrate v4.20.1's actual minimum; the toolchain image is newer |
| PostgreSQL | 17.6 | `deploy/dev/docker-compose.yml` (`postgres:17.6`), `.github/workflows/ci.yml` service container | |
| Node.js | 22.23.2 | `scripts/dev.sh`/`dev.ps1` (`node:22.23.2` image), `.github/workflows/ci.yml` | Build-time only; no Node server ships in production |
| Svelte | 5.57.0 | `web/admin/package.json` | |
| Vite | 8.3.0 | `web/admin/package.json` | |
| TypeScript | 6.0.2 | `web/admin/package.json` | |
| svelte-check | 4.7.6 | `web/admin/package.json` | |
| @sveltejs/vite-plugin-svelte | 7.3.0 | `web/admin/package.json` | |
| @tsconfig/svelte | 5.0.8 | `web/admin/package.json` | |
| bits-ui | 2.19.2 | `web/admin/package.json` | |
| golang-migrate | v4.20.1 | `go.mod` | Requires Go >= 1.25.11, which is why the Go pin above moved from an earlier 1.24 |
| pgx (jackc) | v5.11.0 | `go.mod` | |
| golang-jwt / go-oidc / oauth2 | *(not yet pinned)* | -- | `internal/oidc` is an interface only until Milestone 4 designs the concrete flow; pinning now would be speculative |
| google/uuid | v1.6.0 | `go.mod` | |
| gopkg.in/yaml.v3 | v3.0.1 | `go.mod` | |
| getkin/kin-openapi | v0.149.0 | `go.mod` (test-only, `api/validate_test.go`) | |
| golangci-lint | *(resolved by CI action, see `.github/workflows/ci.yml`)* | `.github/workflows/ci.yml` | Pinned indirectly via the pinned `golangci-lint-action` version |
| Caddy | 2.10.2 | `deploy/dev/docker-compose.yml` | Two-host TLS test stack, and stands in for the protected application backend in the real-Traefik integration test -- not a production component either way |
| alpine/openssl | digest `sha256:f6def4887e8413b228b66f314d0bcf5c25b128d918a258f3b0b9d66a0327edcb` (OpenSSL 3.5.8) | `scripts/gen-certs.sh`/`.ps1`, `scripts/gen-mtls-certs.sh`/`.ps1` | Dev cert generation only; pinned by digest since this image publishes no version tags |
| Traefik | v3.6.25 | `deploy/dev/docker-compose.yml` | Real-Traefik integration test only (Milestone 2) -- `deploy/dev/traefik/dynamic.yml` mirrors spec section 6's example almost verbatim, still using `trustForwardHeader: true` per that example; spec section 20 flags that setting as deprecated in some documentation versions and asks it be re-checked, which hasn't happened yet |
| gcr.io/distroless/static-debian12 | tag `nonroot` (digest-pinned in `Dockerfile`) | `Dockerfile` | Runtime base image for the service binaries |
