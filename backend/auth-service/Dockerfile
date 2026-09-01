# syntax=docker/dockerfile:1.7
# ----------------------------------------------------------------------------
# Multi-stage build for the auth-service. Mirrors the key-service's
# shape: static Go binary in a minimal alpine runtime.
#
# IMPORTANT: this Dockerfile expects the build context to be the
# monorepo ROOT (iceq/), not backend/. All COPY paths below are
# repo-root-relative. docker-compose.yml wires this with:
#   context: ../          # from iceq/deploy/ -> iceq/
#   dockerfile: backend/auth-service/Dockerfile
#
# VERSION is baked into the binary via -ldflags so the running
# container reports its own commit hash in /api/auth/health.
# ----------------------------------------------------------------------------

# ---- Stage 1: builder --------------------------------------------------------
FROM golang:1.27.0-alpine AS builder
WORKDIR /src

# Module download layer. The go.mod / go.sum live at backend/go.mod
# in the monorepo; the auth-service is one of the modules in the
# backend module, so a single go.mod covers it.
COPY backend/go.mod backend/go.sum ./
RUN go mod download

# Source. Copy only the auth-service tree and the shared/ packages
# it imports. This keeps the build cache hot when unrelated services
# change and avoids leaking other directories into the image.
COPY backend/auth-service/  ./auth-service/
COPY backend/file-service/minio/ ./file-service/minio/
COPY backend/shared/        ./shared/

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w -X main.VERSION=${VERSION}" \
    -o /out/auth-service ./auth-service

# ---- Stage 2: runtime --------------------------------------------------------
FROM alpine:3.20 AS runtime

RUN apk add --no-cache ca-certificates wget && \
    addgroup -S iceq && adduser -S iceq -G iceq

COPY --from=builder --chown=iceq:iceq /out/auth-service /usr/local/bin/auth-service

USER iceq
EXPOSE 8080

# wget is included (vs the key-service's no-wget image) so the
# container's own /healthcheck can run `wget --spider` without
# shipping a separate healthcheck binary.
ENTRYPOINT ["/usr/local/bin/auth-service"]
