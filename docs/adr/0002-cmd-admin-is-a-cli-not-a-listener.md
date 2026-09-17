# 0002: `cmd/admin` is an operator CLI, not a network listener

Status: Accepted. Date: 2026-09-17.

## Context

Spec section 2 says one image/binary exposes all four network listeners
(Public, Admin, Authorization, Ops). Spec section 18's suggested
repository layout separately lists both `cmd/server` and `cmd/admin`,
without saying what `cmd/admin` actually does. Spec section 9 mentions
"provide a deployment CLI command to revoke sessions by issuer/subject
for urgent removal," and section 13 mentions bootstrapping applications
"through an authenticated CLI or admin UI."

## Decision

`cmd/server` is the one real service binary: it binds all four listeners.
`cmd/admin` is a separate operator CLI that talks to PostgreSQL directly
(no network listener of its own) for out-of-band tasks: registering the
first application before any admin UI exists, and force-revoking an
admin session by issuer/subject during an urgent removal.

## Consequences

- `cmd/admin`'s subcommands (`register-application`,
  `revoke-admin-session`) are parsed but return "not implemented" until
  Milestone 4 gives them real bodies backed by `internal/store`.
- This CLI needs its own database credentials (likely `app_runtime`
  membership, or a narrower role if a future milestone decides finer
  grants are worth it) -- not a new concern, since it talks to the same
  PostgreSQL instance the server does, just out-of-band.
- If this interpretation turns out to be wrong once Milestone 4 designs
  the actual bootstrap/operations workflow, revisit this ADR rather than
  silently drifting from it.
