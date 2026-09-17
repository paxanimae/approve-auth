#!/usr/bin/env bash
# Containerized dev commands. No Go/Node/mkcert install is required on the
# host — every command below runs inside a pinned Docker image, mounting the
# repo as a bind volume. See docs/tested-versions.md for why these tags.
set -euo pipefail

# Under Git-Bash/MSYS, paths like /workspace get silently rewritten to a
# Windows path before reaching the Docker CLI. Disable that.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_IMAGE="golang:1.25.14"
NODE_IMAGE="node:22.23.2"

# DEV_NETWORK: set to the docker-compose network (default project name
# yields "traefik-manual-proxy_dev") when a command needs to reach the
# Postgres container started by deploy/dev/docker-compose.yml, e.g.:
#   DEV_NETWORK=traefik-manual-proxy_dev TEST_DATABASE_URL=postgres://... scripts/dev.sh test
go_run() {
  local net_args=()
  if [[ -n "${DEV_NETWORK:-}" ]]; then
    net_args=(--network "${DEV_NETWORK}")
  fi
  docker run --rm \
    -v "${ROOT}:/workspace" \
    -v traefik-manual-proxy-gomod:/go/pkg/mod \
    -w /workspace \
    -e GOCACHE=/workspace/.gocache \
    -e GOFLAGS=-mod=mod \
    -e TEST_DATABASE_URL="${TEST_DATABASE_URL:-}" \
    "${net_args[@]}" \
    "${GO_IMAGE}" "$@"
}

node_run() {
  docker run --rm \
    -v "${ROOT}/web/admin:/workspace" \
    -w /workspace \
    "${NODE_IMAGE}" "$@"
}

cmd="${1:-}"
shift || true

case "$cmd" in
  build)      go_run go build ./... ;;
  vet)        go_run go vet ./... ;;
  test)       go_run go test ./... -race "$@" ;;
  tidy)       go_run go mod tidy ;;
  fmt)        go_run gofmt -l -w . ;;
  web-install) node_run npm install ;;
  web-build)  node_run npm run build ;;
  web-check)  node_run npm run check ;;
  shell)      go_run bash ;;
  *)
    echo "Usage: scripts/dev.sh {build|vet|test|tidy|fmt|web-install|web-build|web-check|shell}" >&2
    exit 1
    ;;
esac
