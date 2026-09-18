# Backup and restore

Status: procedure written against spec section 13's targets (RPO <=15
minutes, RTO <=60 minutes, daily encrypted backups plus PITR/WAL). **Not
yet exercised as a real restore drill.** Spec section 13 requires
running one before release and quarterly after -- until the first one
actually happens, treat every claim below as a plan, not a guarantee.

## What needs backing up

Only `db`'s PostgreSQL volume. Everything else this service holds is
either derived (the running containers, rebuildable from the image) or
disposable (rate-limit buckets, idempotency records, claim envelopes --
all short-lived by design; losing them on restore just means a few
in-flight browser retries have to start over, not a correctness issue).
Application secrets (Docker Swarm secrets) are backed up separately, by
whatever backs up your Swarm managers' Raft state -- they are not
recoverable from a database backup.

## Daily backups + PITR/WAL

`deploy/stack.yml`'s `db` service is deliberately a single unreplicated
PostgreSQL instance (spec section 13: "this is explicitly a single point
of failure"; use a real HA PostgreSQL service instead for HA production,
not the baseline in this repo). Whatever backup mechanism you attach to
it needs to give you both:

- **Daily encrypted full backups** -- `pg_basebackup` piped through
  encryption at rest, or your storage layer's own encrypted-snapshot
  feature if the `db-data` volume driver you swapped in (per
  `docs/runbooks/rollout-rollback.md`'s reminder that the default
  `local` driver doesn't survive node loss) supports it.
- **Continuous WAL archiving** for point-in-time recovery between daily
  fulls -- `archive_mode = on` with `archive_command` shipping WAL
  segments to the same encrypted storage, or your managed PostgreSQL
  provider's built-in PITR if you're not self-hosting `db` at all.

This repo does not ship a specific backup tool wiring (no
`pg_basebackup`/WAL-G/pgBackRest sidecar container in `deploy/stack.yml`)
-- picking one is an infrastructure decision tied to where `db-data`
actually lives (cloud block storage vs. bare-metal), not something a
generic stack file should hardcode. Document your actual choice here
once made.

## Restore drill procedure

1. **Provision a separate, isolated environment** -- never restore onto
   a database anything else is still connected to.
2. **Restore the full backup**, then **replay WAL** up to your target
   recovery point (or the latest available, for a "how current can we
   get" drill).
3. **Bring up one `approve-auth` replica against the restored
   database only**, with `admin migrate-up` run first if the backup
   predates a schema migration you've since applied going forward isn't
   possible without also restoring matching application code -- restore
   the image digest that was running *at backup time*, migrate forward
   from there if needed, matching what production actually did.
4. **Verify, don't just assume:**
   - `GET /readyz` returns 200.
   - A known-good test application (register one specifically for drills,
     never reuse a real one) round-trips: request access, approve it,
     claim it, confirm `/auth` allows.
   - Query `audit_events` for a row you know existed before the backup
     point and confirm it survived.
   - Compare row counts for `applications`, `authorizations`, and
     `audit_events` against what you expected from the backup's known
     point in time -- a restore that "looks fine" but silently dropped
     rows is worse than one that visibly failed.
5. **Time the whole thing.** Spec section 13's target is RTO <=60
   minutes end to end (detecting the need to restore is not included in
   that budget -- time only the restore-and-verify steps above). If it
   takes longer, that's the actual finding this drill exists to produce;
   record it and fix whatever's slow before the target date, don't
   silently miss it.
6. **Record the RPO you actually achieved** -- how old was the most
   recent transaction you successfully recovered, relative to whatever
   simulated failure point you chose. Compare against the <=15-minute
   target.
7. **Tear down the drill environment.** Never leave a restored copy of
   production data (including real admin OIDC subjects and audit trails)
   sitting in an isolated environment indefinitely -- it's still the
   same sensitive data spec section 12 governs the retention of.

## Results log

*(Empty. Fill in after the first real drill: date, RPO achieved, RTO
achieved, what broke, what you fixed as a result. A backup/restore
procedure nobody has run is a hope, not a plan -- this section existing
empty is the honest state of that plan today.)*
