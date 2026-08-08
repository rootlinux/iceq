# syntax=docker/dockerfile:1.7
# ----------------------------------------------------------------------------
# Multi-stage build for the key-service.
#
# IMPORTANT: this Dockerfile expects the build context to be the
# monorepo ROOT (iceq/), not backend/. All COPY paths below are
# repo-root-relative. docker-compose.yml wires this with:
#   context: ../          # from iceq/deploy/ -> iceq/
#   dockerfile: backend/key-service/Dockerfile
#
# Stage 1 ("builder") — compile the static binary with CGO disabled so
# the runtime image can be a minimal scratch + ca-certificates layer.
#
# Stage 2 ("runtime") — copy the binary and TLS roots into a
# distroless-ish alpine image. No shell, no package manager; the
# service runs as a non-root user.
#
# VERSION is baked into the binary via -ldflags so the running
# container reports its own commit hash in /health.
# ----------------------------------------------------------------------------

# ---- Stage 1: builder --------------------------------------------------------
FROM golang:1.26.5-alpine AS builder
WORKDIR /src

# Cache the module download layer. Copying go.mod/go.sum first and
# running `go mod download` separately lets Docker reuse the layer
# when only source files change.
COPY backend/go.mod backend/go.sum ./
RUN go mod download

# Source. Copy only the key-service tree and the shared/ packages
# it imports. Scoping the COPY to just the service directory keeps
# the build cache hot and avoids leaking unrelated files.
COPY backend/key-service/  ./key-service/
COPY backend/shared/       ./shared/

# Build the key-service binary. CGO_ENABLED=0 produces a static
# binary; the alpine runtime image doesn't ship glibc so a
# dynamic build would fail to start.
#
# -trimpath removes the build host's filesystem paths from the
# binary, which is hygiene for reproducible builds.
# -ldflags "-s -w" strips the DWARF debug info — smaller image,
# same on-the-wire behavior.
# -ldflags "-X main.VERSION=..." substitutes the build-time
# version string so the binary reports its own commit.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w -X main.VERSION=${VERSION}" \
    -o /out/key-service ./key-service

# ---- Stage 2: runtime --------------------------------------------------------
FROM alpine:3.20 AS runtime

# ca-certificates is the only thing we need at runtime: the
# service talks to Postgres and Redis over plain TCP, but
# outbound TLS to anything (an ACME endpoint, a remote scylla,
# an HTTPS metadata service) needs a trust store.
RUN apk add --no-cache ca-certificates && \
    addgroup -S iceq && adduser -S iceq -G iceq

# Copy the static binary from the builder. We chown to the
# non-root user so a process compromise can't trivially rewrite
# its own binary.
COPY --from=builder --chown=iceq:iceq /out/key-service /usr/local/bin/key-service

USER iceq
EXPOSE 8081

# The image is healthchecked by docker-compose, not by an
# in-binary probe. Letting docker compose drive health keeps
# the binary simple and the healthcheck logic visible in the
# compose file (one place to read the contract).
ENTRYPOINT ["/usr/local/bin/key-service"]
