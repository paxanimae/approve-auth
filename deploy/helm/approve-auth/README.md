# approve-auth Helm chart

A Kubernetes port of [`deploy/stack.yml`](../stack.yml), this project's
own Docker Swarm production deployment. Same topology (a bundled,
single-replica Postgres + a one-off migration step + two
`approve-auth` replicas), same environment-variable and secret-file
conventions, same read-only/non-root/capability-dropped hardening.
Where the two genuinely have to differ, it's called out below rather
than silently changed.

If you already run `deploy/stack.yml`, your existing
`approve-auth-config.yaml` needs **no edits** to become this chart's
`config:` value — only *where the secrets come from* changes
(`kubectl create secret` instead of `docker secret create`).

## What's identical to `deploy/stack.yml`

- Every `*_FILE` environment variable and the exact `/run/secrets/<name>`
  path it points at.
- `admin_origin`, `trusted_traefik_cidrs`, and every other config key —
  the whole `config:` value is `deploy/approve-auth-config.example.yaml`
  verbatim.
- `readOnlyRootFilesystem`, capabilities dropped to nothing, non-root.
- Resource limits/requests (2 vCPU / 512Mi limit, 0.5 vCPU / 256Mi
  request per spec section 15's load-test baseline).
- `terminationGracePeriodSeconds: 30` (`stop_grace_period` in compose).
- Two replicas, preferring separate nodes (`podAntiAffinity`, the
  Kubernetes analogue of `deploy.placement.max_replicas_per_node`).
- The migration step runs to completion before `approve-auth` starts,
  every release (a Helm `pre-install`/`pre-upgrade` hook Job, instead
  of a Swarm one-off service).
- Secrets are referenced by name, never templated from a literal value
  in `values.yaml` — the same `external: true` philosophy, for the
  same reason (a literal secret value in a Helm values file ends up
  readable in `helm get values`/`helm history` forever).

## What's different, and why

| `deploy/stack.yml` | This chart | Why |
|---|---|---|
| `docker secret create` | `kubectl create secret` | No Kubernetes equivalent of a Swarm secret; a K8s Secret is the closest analogue and this chart only ever references one by name. |
| `docker config create approve-auth-config` (external) | A ConfigMap this chart creates itself from `values.config` | Kubernetes ConfigMaps are namespaced and cheap to template; there's no reason to require a separate `kubectl create configmap` step the way Swarm's cluster-wide config object needs. |
| No health checks on `approve-auth` (Swarm relies on container exit status) | `readinessProbe`/`livenessProbe` against `GET /readyz` / `GET /livez` | The service already exposes exactly these endpoints for this purpose (spec section 13) — Kubernetes expects probes wired, so this fills a gap rather than changing behavior. |
| `traefik.*` Swarm service labels | Optional `Middleware`/`IngressRoute` (`traefik.io/v1alpha1`) CRDs, `traefik.enabled` | Kubernetes has no per-Pod-label ingress discovery the way Traefik's Swarm provider does; the CRDs are the closest equivalent **if** Traefik itself runs as your cluster's ingress. Not validated against a live cluster — verify the `tls` sub-fields against your installed Traefik CRD version first. |
| `docker config create approve-auth-ca-bundle` / GeoIP bind mount | `caBundle.existingConfigMap` / `geoip.hostPath` or `geoip.existingClaim` | GeoIP's ~60MB file exceeds a ConfigMap's 1MiB (etcd) limit, so it needs a real volume — `hostPath` carries the exact same "pinned to one node, doesn't survive node loss" caveat `deploy/stack.yml`'s own commented-out bind mount already documents. |
| Local `local` volume driver for `db-data` | `volumeClaimTemplates` (any `StorageClass`) | Kubernetes' own primitive for exactly this; still a single point of failure at one replica either way, per spec section 13. |

## Prerequisites, in order

These mirror `deploy/stack.yml`'s own prerequisite comment block and
`docs/runbooks/rollout-rollback.md` — read those first if anything
below is unclear about *why*, not just *how*.

1. **Bundled Postgres, or bring your own.** `db.enabled: true` (the
   default) creates a single-replica StatefulSet for you. If you'd
   rather point at a managed Postgres (the `deploy/stack.approve.yml`
   equivalent), set `db.enabled: false` and skip to step 4.

2. **Create the superuser credential the bundled Postgres itself reads
   at startup**, and the migration Job's own connection string (kept
   as two separate secrets, like compose, rather than one this chart
   would have to template a connection string out of):

   ```bash
   kubectl create secret generic approve-auth-db-superuser \
     --from-literal=db_superuser_name=postgres \
     --from-literal=db_superuser_password="$(openssl rand -base64 24)"

   # Once you know the bundled Postgres's Service DNS name (see NOTES.txt
   # after a first `helm install`, or predict it as
   # <release>-approve-auth-db.<namespace>.svc.cluster.local):
   kubectl create secret generic approve-auth-database-url-superuser \
     --from-literal=database_url_superuser='postgresql://postgres:<same password>@<release>-approve-auth-db:5432/approve_auth?sslmode=disable'
   ```

   Set `db.existingSecret: approve-auth-db-superuser` and
   `db.existingSuperuserUrlSecret: approve-auth-database-url-superuser`.

3. **Create the remaining application secrets** (see
   `docs/runbooks/rollout-rollback.md` for what each one actually
   guards):

   ```bash
   kubectl create secret generic approve-auth-oidc-client-secret \
     --from-literal=oidc_client_secret='<your real IdP client secret>'
   kubectl create secret generic approve-auth-claim-encryption-key \
     --from-literal=claim_encryption_key="$(openssl rand -base64 32)"
   kubectl create secret generic approve-auth-oidc-state-key \
     --from-literal=oidc_state_key="$(openssl rand -base64 32)"
   kubectl create secret generic approve-auth-auth-tls-cert --from-file=auth_tls_cert=<path>
   kubectl create secret generic approve-auth-auth-tls-key --from-file=auth_tls_key=<path>
   kubectl create secret generic approve-auth-auth-client-ca --from-file=auth_client_ca=<path>
   ```

   Point `secrets.*` in your values override at each of these names.

4. **`helm install` once with only the migration prerequisites met**
   (the pre-install hook needs `db.existingSuperuserUrlSecret` to
   exist; the main Deployment will crash-loop until step 5 below is
   also done, which is expected — same order compose forces via its
   own prerequisite steps 3/4).

5. **Create the app's own least-privileged runtime role** (migration
   000012 only ever creates a fixed dev/CI-convenience role,
   `approve_auth_app`/`devpassword` — never use that in production):

   ```bash
   kubectl run -it --rm psql --image postgres:17.6 --restart=Never -- \
     psql "<database_url_superuser value>" -c "
       CREATE ROLE approve_prod_runtime LOGIN PASSWORD '<a real random password>';
       GRANT app_runtime TO approve_prod_runtime;
     "

   kubectl create secret generic approve-auth-database-url \
     --from-literal=database_url='postgresql://approve_prod_runtime:<that password>@<release>-approve-auth-db:5432/approve_auth?sslmode=disable'
   ```

   Point `secrets.databaseUrl` at this secret's name, then
   `helm upgrade` to pick it up.

6. **Edit `values.yaml`'s `config:` block** (or supply `-f
   myvalues.yaml`) with your real `admin_origin`, `oidc_issuer`,
   `oidc_client_id`, `oidc_admin_groups`/`oidc_viewer_groups`,
   `auth_allowed_client_identities`, and `trusted_traefik_cidrs` —
   exactly the same edits `deploy/approve-auth-config.example.yaml`
   itself asks for.

7. **Set `adminHostname`** to the real admin console hostname.

8. **Optional**: `caBundle.enabled` / `geoip.enabled` — see the
   comments beside each in `values.yaml`.

9. **Optional**: `traefik.enabled` (default `true`) needs
   `traefik.mtls.caSecret` and `traefik.mtls.certSecret` — the same two
   pieces `deploy/traefik-approve-auth-middleware.yml`'s own `tls:`
   block needs, as Kubernetes Secrets. Set `traefik.enabled: false` and
   wire your own ingress by hand if you're not running Traefik as this
   cluster's ingress.

```bash
helm upgrade --install approve-auth ./deploy/helm/approve-auth \
  -f myvalues.yaml
```
