# syntax=docker/dockerfile:1.7
# ----------------------------------------------------------------------------
# Multi-stage build for the presence-service.
#
# IMPORTANT: this Dockerfile expects the build context to be the
# monorepo ROOT (iceq/), not backend/. All COPY paths below are
# repo-root-relative. docker-compose.yml wires this with:
#   context: ../          # from iceq/deploy/ -> iceq/
#   dockerfile: backend/presence-service/Dockerfile
#
# Stage 1 ("builder") — compile the static binary with CGO disabled.
# Stage 2 ("runtime") — copy the binary into a minimal alpine image.
# No shell, no package manager; the service runs as a non-root user.
#
# VERSION is baked into the binary via -ldflags so the running
# container reports its own commit hash in /health.
# ----------------------------------------------------------------------------

# ---- Stage 1: builder --------------------------------------------------------
FROM golang:1.26.5-alpine AS builder
WORKDIR /src

# Module download layer. The go.mod / go.sum live at backend/go.mod
# in the monorepo; the presence-service is one of the modules in
# the backend module, so a single go.mod covers it.
COPY backend/go.mod backend/go.sum ./
RUN go mod download

# Source. Copy only the presence-service tree and the shared/
# packages it imports. This keeps the build cache hot when
# unrelated services change and avoids leaking other directories
# into the image.
COPY backend/presence-service/  ./presence-service/
COPY backend/shared/           ./shared/

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w -X main.VERSION=${VERSION}" \
    -o /out/presence-service ./presence-service

# ---- Stage 2: runtime --------------------------------------------------------
FROM alpine:3.20 AS runtime

RUN apk add --no-cache ca-certificates wget && \
    addgroup -S iceq && adduser -S iceq -G iceq

COPY --from=builder --chown=iceq:iceq /out/presence-service /usr/local/bin/presence-service

USER iceq
EXPOSE 8080

# wget is included so the container's own /healthcheck can run
# `wget --spider` without shipping a separate healthcheck binary.
ENTRYPOINT ["/usr/local/bin/presence-service"]
