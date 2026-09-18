# Secret and key rotation

Status: procedure written against the actual code paths that read each
secret (cited below); not yet exercised as a live rotation against a
running deployment. Spec section 14: "Certificate/key rotation must be
demonstrated without an allow-all interval" -- read that as the bar this
document has to clear once actually run, not yet claimed as met.

Docker Swarm secrets are immutable once created: you cannot edit
`claim_encryption_key` in place, you create `claim_encryption_key_v2`,
point the service at it, and remove the old one once nothing references
it anymore. Every rotation below follows that same three-step shape.

## `CLAIM_ENCRYPTION_KEY` (claim-retry envelope encryption)

Read by `internal/enrollment`'s `envelope.go` to encrypt/decrypt the
short-lived (10-minute) claim-retry envelope (spec section 5). There is
**no overlap window needed** for this one specifically: envelopes expire
in 10 minutes on their own, so a rotation that briefly can't decrypt an
in-flight envelope just means that one browser's retry falls back to
"request access again" -- annoying, not a security or correctness
problem, and bounded to at most a 10-minute impact window.

1. Generate a new key: `openssl rand -base64 32`.
2. Create it under a new secret name: `docker secret create claim_encryption_key_v2 -`.
3. Update `deploy/stack.yml`'s `approve-auth` service to reference
   `claim_encryption_key_v2` (and bump `claim_encryption_key_id` in the
   nonsecret config if you version-tag envelopes by key ID -- see spec
   section 11 control 8: "Rotate encryption keys with key IDs").
4. `docker stack deploy -c deploy/stack.yml approve-auth`. Once every
   replica is on the new key (`docker stack ps approve-auth` shows no
   old-image/old-secret tasks), remove the old secret:
   `docker secret rm claim_encryption_key`.

## `OIDC_STATE_ENCRYPTION_KEY` (admin login PKCE-verifier encryption)

Read by `internal/adminsession` to encrypt the PKCE verifier during the
OIDC Authorization Code flow (spec section 9), for the 10-minute
`oidc_transactions` window. Same reasoning as above: rotating this
mid-flight just fails one in-progress login attempt, which the admin
simply retries. No overlap window needed.

Same three steps as `CLAIM_ENCRYPTION_KEY` above, with
`oidc_state_key`/`oidc_state_key_v2`.

## `DATABASE_URL` (runtime database credential)

1. Create a new PostgreSQL role, grant it `app_runtime` membership:
   ```sql
   CREATE ROLE approve_auth_app_v2 LOGIN PASSWORD '...';
   GRANT app_runtime TO approve_auth_app_v2;
   ```
2. `docker secret create database_url_v2 -` with the new role's
   connection string.
3. Update `deploy/stack.yml` to reference it, redeploy.
4. Once the rollout finishes, revoke the old role's membership and drop
   it: `REVOKE app_runtime FROM approve_auth_app; DROP ROLE approve_auth_app;`,
   then `docker secret rm database_url`.

The maintenance-role credential (`cmd/admin purge-audit-log`'s
`DATABASE_URL_FILE`) isn't a long-lived service secret at all -- it's
supplied per-invocation of that one-shot command (see
`docs/runbooks/backup-restore.md` and the cron/Swarm job that runs it),
so "rotating" it just means changing what that job's own credential
source hands it, with no running-service overlap concern.

## `OIDC_CLIENT_SECRET`

Rotate on your identity provider's side first (most providers let a
confidential client have two valid secrets briefly), then:
`docker secret create oidc_client_secret_v2 -`, update the stack,
redeploy, remove the old secret, then invalidate the old secret on the
IdP side once no replica references it.

## `AUTH_TLS_CERT_FILE`/`AUTH_TLS_KEY_FILE` and `AUTH_CLIENT_CA_FILE`

These back the mTLS Authorization listener (spec section 2: "Traefik
only, mTLS required"). Unlike the encryption keys above, a mismatch here
is fail-*closed*, not silently degraded: Traefik's ForwardAuth call to
`/auth` starts failing its TLS handshake the moment a replica presents a
certificate Traefik's configured CA doesn't trust, or the moment this
service's own `AUTH_CLIENT_CA_FILE` stops trusting Traefik's client
certificate. That means rotation **does** need a real overlap window if
you want zero downtime:

1. Issue the new server certificate/client CA pair, but keep the old
   ones valid too during the transition.
2. Update `AUTH_CLIENT_CA_FILE`'s secret to a bundle containing **both**
   the old and new CA certificates concatenated, and roll that out
   first, before anything else changes. Because `internal/httpserver.AuthTLSConfig`
   builds one `x509.CertPool` from that file, a bundle containing both
   CAs makes every replica accept client certs signed by either one
   during the transition.
3. Roll out the new server certificate/key (`auth_tls_cert`/
   `auth_tls_key`) the same way (new secret name, redeploy, remove old).
4. Have Traefik's own operator switch its client certificate to the one
   signed by the new CA, and update its own trust of this service's
   server certificate if the CA changed there too.
5. Once every replica and Traefik itself are confirmed on the new
   certificates, redeploy `AUTH_CLIENT_CA_FILE` with just the new CA
   (drop the old one from the bundle) and remove the old secrets.

Never skip straight to a CA bundle containing *only* the new CA while
any replica or Traefik is still presenting the old certificate -- that
is exactly the "allow-all interval" spec section 14 says this rotation
must avoid, just inverted into a "deny-all interval" instead. Verify
with a real handshake (`openssl s_client -connect approve-auth:8443
-cert ... -key ... -CAfile ...` from a container on the same overlay)
before removing the old trust, not just by reading the deploy succeeded.

## Admin session urgent revocation

Not a key rotation, but the closest urgent-response cousin: to cut off
one admin's access immediately (compromised account, offboarding)
without waiting for their session to expire naturally:

```bash
docker run --rm --network approve-auth_db \
  -e CONFIG_FILE=/config/approve-auth.yaml \
  -e DATABASE_URL_FILE=/run/secrets/database_url \
  ... \
  "$APPROVE_AUTH_IMAGE" \
  admin revoke-admin-session -issuer https://login.example.com/ -subject <their-oidc-subject>
```

This works even if the identity provider itself is unreachable (spec
section 9: "Existing sessions can continue until expiry during provider
outage unless locally revoked") -- it only touches this service's own
`admin_sessions` table.
