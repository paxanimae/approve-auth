# 0001: Migration tool -- golang-migrate

Status: Accepted. Date: 2026-09-17.

## Context

The schema (spec section 8) needs plain DDL: tables, `CHECK` constraints,
composite foreign keys, and `GRANT`/`REVOKE`/`CREATE ROLE` for the audit-
immutability design. Two mainstream Go options exist: `golang-migrate`
(plain SQL files, both a CLI and an importable library) and `goose`
(supports Go-code migrations for logic SQL can't express, in addition to
SQL files).

## Decision

Use `golang-migrate/migrate/v4`, with plain numbered SQL files
(`NNNNNN_description.{up,down}.sql`), one migration per table, embedded
into the binary via `go:embed` + the `source/iofs` driver.

## Rationale

Nothing in this schema needs Go-code migrations -- goose's main
differentiator over golang-migrate isn't needed here. golang-migrate's
`iofs` source reads directly from an `embed.FS`, so the exact same
migration files run identically via its standalone CLI (manual ops),
`internal/store.MigrateUp`/`MigrateDown` at service startup, and in Go
tests -- no drift between what CI tested and what the binary runs.
One-migration-per-table (rather than one large migration) keeps review
and bisection simple and maps directly to the dependency graph the
composite FKs require (see `migrations/000004`, `000005`).

## Consequences

- `migrations/embed.go` exists solely to expose `embed.FS` to
  `internal/store`, since `go:embed` can't reach outside the importing
  package's own directory tree and the spec's repo layout keeps
  `migrations/` at the repo root, not nested under `internal/store/`.
- Role creation (migration `000012`) requires the connecting user to have
  role-creation privileges -- fine for local/CI (a superuser role) and
  for the "one-off, locked migration step" production deployment model
  spec section 13 describes, but this is a real operational requirement
  to document in the eventual deploy runbook.
