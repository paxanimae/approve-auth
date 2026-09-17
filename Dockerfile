# See docs/tested-versions.md for why these exact tags.
FROM golang:1.25.14 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/server ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -o /out/admin ./cmd/admin

# distroless:nonroot runs as uid/gid 65532 -- no shell, no package
# manager, nothing beyond the binary and its runtime deps (spec section
# 13: "nonroot user"). Read-only filesystem, dropped capabilities, and a
# writable tmpfs where needed are runtime (compose/Swarm) settings, not
# baked into the image -- see deploy/dev/docker-compose.yml.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/server /usr/local/bin/server
COPY --from=build /out/admin /usr/local/bin/admin
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/server"]
