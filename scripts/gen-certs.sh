#!/usr/bin/env bash
# Generates self-signed dev-only TLS certs for the two-host local test
# stack (deploy/dev/docker-compose.yml's app-a/app-b services), entirely
# inside a container -- nothing is installed or trusted on this machine.
#
# This means browsers will show a certificate warning when visiting
# https://app-a.localtest.me:10443 / https://app-b.localtest.me:10444 --
# that's expected. (The original plan used mkcert, which installs a
# locally-trusted CA into the OS/browser trust store; that's a host-side
# change we deliberately don't make here. If you want the no-warning
# experience, install mkcert yourself and trust deploy/dev/certs/ca.pem --
# that's your call, not something this script does for you.)
set -euo pipefail
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS_DIR="${ROOT}/deploy/dev/certs"
OPENSSL_IMAGE="alpine/openssl@sha256:f6def4887e8413b228b66f314d0bcf5c25b128d918a258f3b0b9d66a0327edcb"

mkdir -p "${CERTS_DIR}"

gen_host_cert() {
  local host="$1"
  docker run --rm -v "${CERTS_DIR}:/certs" "${OPENSSL_IMAGE}" req -x509 -nodes \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -days 365 \
    -keyout "/certs/${host}-key.pem" \
    -out "/certs/${host}.pem" \
    -subj "/CN=${host}" \
    -addext "subjectAltName=DNS:${host}"
}

gen_host_cert "app-a.localtest.me"
gen_host_cert "app-b.localtest.me"

echo "Generated self-signed dev certs in ${CERTS_DIR}"
echo "Browsers will show a certificate warning for these -- see this script's header comment."
