# See docs/tested-versions.md for why these exact tags. Build-time only --
# no Node server ships in production; its only output the Go stage needs
# is web/admin/dist, which go:embed requires present at compile time
# (spec section 2: "Serve compiled admin assets from the Go binary").
FROM node:22.23.2@sha256:8a34c4ab3ea2c5cd194f07e317b2a8f09461d3c8b05c4e34c8ccd56d56024c4d AS web
WORKDIR /src/web/admin
COPY web/admin/package.json web/admin/package-lock.json ./
RUN npm ci
COPY web/admin/ ./
RUN npm run build

FROM golang:1.25.14@sha256:699337d620559a59b4a2bb298ad59611e535d2ee755a34cf2d2a98f37578dc80 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/admin/dist ./web/admin/dist
RUN CGO_ENABLED=0 go build -trimpath -o /out/server ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -o /out/admin ./cmd/admin
RUN CGO_ENABLED=0 go build -trimpath -o /out/mock-oidc ./cmd/mock-oidc

# distroless:nonroot runs as uid/gid 65532 -- no shell, no package
# manager, nothing beyond the binary and its runtime deps (spec section
# 13: "nonroot user"). Read-only filesystem, dropped capabilities, and a
# writable tmpfs where needed are runtime (compose/Swarm) settings, not
# baked into the image -- see deploy/dev/docker-compose.yml.
#
# This is the default (last) stage, and the one production actually
# ships: docker build with no --target produces this image. The
# mock-oidc dev-tool stage below is only ever built by explicitly naming
# its target (see deploy/dev/docker-compose.yml's mock-oidc service).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime
COPY --from=build /out/server /usr/local/bin/server
COPY --from=build /out/admin /usr/local/bin/admin
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/server"]

# mock-oidc is a real (not stubbed) OIDC provider for local dev and the
# real-Traefik integration stack only (see cmd/mock-oidc's doc comment) --
# it is never the default build target and never part of a release image.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS mock-oidc
COPY --from=build /out/mock-oidc /usr/local/bin/mock-oidc
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/mock-oidc"]
