# Runbooks

Operational runbooks for `deploy/stack.yml` (spec section 13 and
Milestone 5's exit gate):

- [`rollout-rollback.md`](./rollout-rollback.md) -- first-time
  deployment, rolling upgrades, and manual rollback.
- [`key-rotation.md`](./key-rotation.md) -- rotating every secret this
  service reads, and urgent admin-session revocation.
- [`backup-restore.md`](./backup-restore.md) -- what to back up and the
  restore-drill procedure.
- [`load-testing.md`](./load-testing.md) -- how to run spec section 15's
  baseline load test and what to measure.

Each one says explicitly, near the top, whether it has actually been
exercised against a real deployment yet or is still a reasoned-through
plan -- read that status line before trusting a runbook under pressure.
