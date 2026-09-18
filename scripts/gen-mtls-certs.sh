#!/usr/bin/env bash
# Generates a dev-only CA plus a server cert (the approve-auth
# service's Authorization listener identity) and a client cert (what
# Traefik presents to it), entirely inside a container -- nothing
# installed or trusted on this machine. Used by the real-Traefik
# integration test and by deploy/dev/docker-compose.yml's traefik service.
set -euo pipefail
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${ROOT}/deploy/dev/mtls"
OPENSSL_IMAGE="alpine/openssl@sha256:f6def4887e8413b228b66f314d0bcf5c25b128d918a258f3b0b9d66a0327edcb"

mkdir -p "${DIR}"

run_openssl() {
  docker run --rm -v "${DIR}:/certs" -w /certs "${OPENSSL_IMAGE}" "$@"
}

run_openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 3650 \
  -keyout ca-key.pem -out ca-cert.pem -subj "/CN=approve-auth-dev-ca"

# Server identity for the Authorization listener. SAN matches the
# service's Swarm DNS/VIP name (spec section 13).
run_openssl req -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout server-key.pem -out server.csr -subj "/CN=approve-auth" \
  -addext "subjectAltName=DNS:approve-auth"
run_openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out server-cert.pem -days 365 -copy_extensions copyall

# Traefik's own client identity -- must match AUTH_ALLOWED_CLIENT_IDENTITIES.
run_openssl req -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout traefik-client-key.pem -out traefik-client.csr -subj "/CN=traefik-client"
run_openssl x509 -req -in traefik-client.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out traefik-client-cert.pem -days 365

rm -f "${DIR}"/*.csr "${DIR}"/*.srl

echo "Generated dev mTLS material in ${DIR}"
