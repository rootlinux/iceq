# syntax=docker/dockerfile:1.7
# ----------------------------------------------------------------------------
# Multi-stage build for the ws-gateway.
#
# IMPORTANT: this Dockerfile is intended to be built with the build
# context set to the monorepo ROOT (iceq/), NOT to backend/. Every
# COPY path below is repo-root-relative for that reason.
#
# docker-compose.yml wires this up as:
#   build:
#     context: ../          # -> /Users/.../iceq
#     dockerfile: backend/ws-gateway/Dockerfile
#
# Stage 1 ("builder") — compile a static binary with CGO disabled.
# Stage 2 ("runtime") — copy the binary into a minimal alpine image.
# No shell, no package manager; the service runs as a non-root user.
#
# VERSION is baked into the binary via -ldflags so the running
# container reports its own commit hash in /health.
# ----------------------------------------------------------------------------

# ---- Stage 1: builder --------------------------------------------------------
FROM golang:1.25.12-alpine AS builder
WORKDIR /src

# Module download layer. The go.mod / go.sum live at backend/go.mod
# in the monorepo; the ws-gateway is one of the modules in the
# backend module, so a single go.mod covers it.
COPY backend/go.mod backend/go.sum ./
RUN go mod download

# Source. Copying only the ws-gateway tree plus the shared/ packages
# it imports keeps the build cache hot when unrelated services change.
# The build context is the repo root, so all paths are repo-relative.
COPY backend/ws-gateway/  ./ws-gateway/
COPY backend/shared/      ./shared/

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w -X main.VERSION=${VERSION}" \
    -o /out/ws-gateway ./ws-gateway

# ---- Stage 2: runtime --------------------------------------------------------
FROM alpine:3.24 AS runtime

RUN apk add --no-cache ca-certificates && \
    addgroup -S iceq && adduser -S iceq -G iceq

COPY --from=builder --chown=iceq:iceq /out/ws-gateway /usr/local/bin/ws-gateway

USER iceq
EXPOSE 8082

ENTRYPOINT ["/usr/local/bin/ws-gateway"]
