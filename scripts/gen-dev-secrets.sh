#!/usr/bin/env bash
# Generates the dev-only secret files deploy/dev/docker-compose.yml's
# migrate/approve-auth services mount from ./secrets (gitignored --
# deploy/dev/secrets/ never exists in a fresh checkout or CI runner).
# None of these are real secrets: the database credentials are the fixed
# dev-only role/password `migrations/000012_roles_and_grants.up.sql`
# already creates for local dev/CI convenience, and the OIDC client
# secret is never checked by cmd/mock-oidc. Only the two AES-256 keys
# are randomly generated, entirely inside a container -- nothing
# installed on this machine -- and only because internal/config
# requires a well-formed 32-byte key, not because their actual value
# matters for a database that's recreated on every run.
#
# Safe to run repeatedly: existing files are left alone, so it never
# clobbers keys a long-running local stack already has data encrypted
# under.
set -euo pipefail
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${ROOT}/deploy/dev/secrets"
OPENSSL_IMAGE="alpine/openssl@sha256:f6def4887e8413b228b66f314d0bcf5c25b128d918a258f3b0b9d66a0327edcb"

mkdir -p "${DIR}"

write_if_missing() {
  local name="$1" value="$2"
  local path="${DIR}/${name}"
  if [[ -f "${path}" ]]; then
    echo "Skipping ${name} (already exists)"
    return
  fi
  printf '%s' "${value}" >"${path}"
  echo "Wrote ${name}"
}

gen_aes_key_if_missing() {
  local name="$1"
  local path="${DIR}/${name}"
  if [[ -f "${path}" ]]; then
    echo "Skipping ${name} (already exists)"
    return
  fi
  docker run --rm "${OPENSSL_IMAGE}" rand -base64 32 | tr -d '\n' >"${path}"
  echo "Wrote ${name}"
}

write_if_missing "database-url-superuser.txt" "postgres://postgres:devpassword@db:5432/approve_auth?sslmode=disable"
write_if_missing "database-url.txt" "postgres://approve_auth_app:devpassword@db:5432/approve_auth?sslmode=disable"
write_if_missing "oidc-client-secret.txt" "dev-placeholder-oidc-client-secret"
gen_aes_key_if_missing "claim-encryption-key.txt"
gen_aes_key_if_missing "oidc-state-key.txt"

echo "Dev secrets ready in ${DIR}"
