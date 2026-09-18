# Rollout, rollback, and initial deployment

Status: written against `deploy/stack.yml` as of Milestone 5. Not yet
exercised against a real multi-node Swarm cluster -- see this repo's
`docs/threat-model.md` section 6 for what that means for confidence
level. Update this runbook the first time it's actually run for real,
not just written.

## First-time deployment

1. **Build and push the image.** `Dockerfile`'s default target
   (`runtime`) is what ships:

   ```bash
   docker build -t <registry>/approve-auth:<tag> .
   docker push <registry>/approve-auth:<tag>
   ```

   Resolve the pushed tag to its digest and use that everywhere below --
   a mutable tag can change under you mid-rollout:

   ```bash
   export APPROVE_AUTH_IMAGE="$(docker inspect --format='{{index .RepoDigests 0}}' <registry>/approve-auth:<tag>)"
   ```

2. **Label a storage node** for PostgreSQL (spec section 13: pin it to
   one labeled node; this is a documented single point of failure, not
   something this step fixes):

   ```bash
   docker node update --label-add approve-auth-db-storage=true <node-id>
   ```

3. **Create secrets.** Every name below matches `deploy/stack.yml`'s
   `secrets:` block exactly:

   | Secret | Contents |
   |---|---|
   | `db_superuser_name` | PostgreSQL superuser role name (e.g. `postgres`) |
   | `db_superuser_password` | That role's password |
   | `database_url_superuser` | `postgres://<superuser>:<password>@db:5432/approve_auth?sslmode=require` -- used only by the one-shot `migrate` service |
   | `database_url` | A connection string for a role that is a member of `app_runtime` only (spec section 11: least privilege) -- `GRANT app_runtime TO <role>;` after the first migration run creates that group role |
   | `oidc_client_secret` | The OIDC confidential client's secret from your identity provider |
   | `claim_encryption_key` | 32 random bytes, base64: `openssl rand -base64 32` |
   | `oidc_state_key` | 32 random bytes, base64, **different** from `claim_encryption_key`: `openssl rand -base64 32` |
   | `auth_tls_cert`, `auth_tls_key` | The Authorization listener's own server certificate/key (SAN must include the Swarm service name `approve-auth`) |
   | `auth_client_ca` | The CA that issued Traefik's client certificate for calling `/auth` |

   ```bash
   printf '%s' 'postgres' | docker secret create db_superuser_name -
   openssl rand -base64 32 | docker secret create claim_encryption_key -
   # ...repeat for every secret in the table above
   ```

   Rotating any of these later means creating a **new** secret under a
   new name, updating the service to reference it, and removing the old
   one only after the rolling update finishes -- see
   `docs/runbooks/key-rotation.md`; Swarm secrets are immutable once
   created.

4. **Prepare the Traefik side.** Whoever manages the shared Traefik
   deployment mounts `deploy/traefik-approve-auth-middleware.yml`
   into its file-provider directory, with `approve_auth_ca`/
   `traefik_client_cert`/`traefik_client_key` secrets attached to
   *their* stack (this repo doesn't own that stack, so it can't create
   those secrets for you) and their entry point configured with
   `forwardedHeaders.insecure=false` plus explicit `trustedIPs` for the
   real upstream load balancer.

5. **Write the real nonsecret config.** Copy
   `deploy/approve-auth-config.example.yaml`, fill in real values,
   and export `CONFIG_PATH` to point at it.

6. **Deploy:**

   ```bash
   export ADMIN_HOSTNAME=approval-admin.example.com
   export TRAEFIK_CERT_RESOLVER=default   # or your resolver's real name
   docker stack deploy -c deploy/stack.yml approve-auth
   ```

   Watch `migrate` reach `Complete` before `approve-auth` starts
   accepting traffic (Swarm handles the ordering via `depends_on`-less
   compose files by simply having `migrate` finish fast; if it's still
   running when you check, wait rather than force anything):

   ```bash
   docker stack ps approve-auth
   ```

7. **Register the first application** (spec section 13/14: "bootstrap
   applications through an authenticated CLI or admin UI"):

   ```bash
   docker run --rm --network approve-auth_db \
     -e CONFIG_FILE=/config/approve-auth.yaml \
     -e DATABASE_URL_FILE=/run/secrets/database_url \
     -v <path-to-real-config>:/config/approve-auth.yaml:ro \
     --mount type=bind,src=<path-to-secret-file>,dst=/run/secrets/database_url,ro \
     "$APPROVE_AUTH_IMAGE" \
     admin register-application -hostname app.example.com -display-name "Example App"
   ```

   (Or run `admin register-application` from any host that can reach
   the database directly with the right role -- it needs no Swarm-
   specific plumbing beyond a reachable `DATABASE_URL_FILE`.)

8. **Onboard that application's own Traefik routing** (spec section 6):
   add the reserved-path router and the `approve-auth@file`
   middleware reference to *that application's own stack*, exactly as
   shown in spec section 6's example -- this repo's stack only ever
   configures its own admin listener's router.

9. **Verify.** `curl` the admin origin's `/auth/login` and confirm it
   redirects to your real IdP; approve a test device end to end.

## Rolling upgrade

```bash
export APPROVE_AUTH_IMAGE="<new digest>"
docker stack deploy -c deploy/stack.yml approve-auth
```

`deploy/stack.yml`'s `update_config` (`order: start-first`,
`parallelism: 1`, `failure_action: rollback`) means Swarm starts one new
replica, waits for its restart policy to consider it healthy, then stops
one old replica, one at a time -- so a bad rollout automatically rolls
itself back rather than taking every replica down together. If the image
changed a migration too, run the `migrate` service's task again first
(re-running `docker stack deploy` re-triggers it, since it always has
`restart_policy: condition: none` and therefore always starts fresh) --
this is the "support mixed application versions during rolling
deployment through expand/contract migrations" requirement (spec section
13): a new migration must be additive/backward-compatible with the
*previous* image still running against it during the rollout window.

## Manual rollback

```bash
export APPROVE_AUTH_IMAGE="<previous known-good digest>"
docker stack deploy -c deploy/stack.yml approve-auth
```

Keep at least the previous digest recorded (spec section 13: "Keep a
previous image digest and compatible schema for rollback") -- write it
down wherever you track deploys, not just in shell history. A schema
change that isn't backward-compatible with the previous image needs a
restore from backup instead of a simple redeploy; see
`docs/runbooks/backup-restore.md`.

## What this runbook has not yet verified

This has been validated as syntactically correct
(`docker compose -f deploy/stack.yml config`) and reasoned through
against spec section 13's requirements, but not yet exercised against a
real multi-node Swarm cluster, a real failure injection during a rolling
update, or a real IdP. Run it for real before relying on it, and update
this document with what you actually observed.
