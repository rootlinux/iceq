# syntax=docker/dockerfile:1.7
# ----------------------------------------------------------------------------
# Multi-stage build for the IceQ web client.
#
# Stage 1 ("builder") — node:20-alpine. We install dependencies
# (npm ci) and run `npm run build`, which produces a Vite
# production build at /app/dist.
#
# Stage 2 ("runtime") — caddy:2-alpine. The static bundle is
# served by the Caddy reverse proxy. Caddy's existing config
# (in deploy/Caddyfile) already wires the routes for /api/*
# and /ws/*; the SPA is served from /srv.
#
# Build context: monorepo root (iceq/). All COPY paths are
# repo-root-relative. docker-compose.yml wires this with:
#   context: ../
#   dockerfile: web/Dockerfile
# ----------------------------------------------------------------------------

# ---- Stage 1: builder ------------------------------------------------------
FROM node:20-alpine AS builder
WORKDIR /app

# Install deps first for cache friendliness. package-lock.json
# is committed; `ci` is the deterministic install.
COPY web/package.json web/package-lock.json* ./
RUN npm ci --no-audit --no-fund

# Source. Copy the whole web/ tree; Vite picks up the
# config + tsconfig from here.
COPY web/ ./

# Build. The script in package.json is `tsc --noEmit && vite
# build` so a type error fails the build before Vite even
# runs.
RUN npm run build

# ---- Stage 2: runtime ------------------------------------------------------
# caddy:2-alpine. The IceQ deploy/Caddyfile is mounted at
# runtime via docker-compose (volume), so we just put the
# static files at /srv and let Caddy serve them.
FROM caddy:2-alpine AS runtime

COPY --from=builder /app/dist /srv
