# Integration tests

Reserved for real-Traefik integration tests (spec section 16) once
Milestone 2 adds ForwardAuth logic and a Traefik instance to test
against. Milestone 1's own integration-level tests (real `net.Listen` on
all four listeners, real PostgreSQL constraint/role checks) live next to
the code they test -- `internal/httpserver/integration_test.go`,
`internal/store/*_test.go` -- since they need no external service beyond
what `docker compose -f deploy/dev/docker-compose.yml` already provides.
