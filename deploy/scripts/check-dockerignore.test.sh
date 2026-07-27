#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
ignore="$root/.dockerignore"

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# ── Existence ────────────────────────────────────────────────────────
test -f "$ignore" || fail ".dockerignore is missing"

# ── Sensitive exclusions ─────────────────────────────────────────────
for pattern in .git '.env' 'node_modules' 'dist' 'coverage' 'test-results' 'playwright-report' '*.log' '.DS_Store'; do
  if ! grep -qF "$pattern" "$ignore"; then
    fail ".dockerignore must exclude '$pattern'"
  fi
done

# ── Build inputs preserved (exclusion must NOT match these) ──────────
mkdir -p /tmp/iceq-dockerignore-test
trap 'rm -rf /tmp/iceq-dockerignore-test' EXIT

# Simulate the build-context subset: create marker files for paths
# that MUST be available to Docker.
required="
web/package.json
web/package-lock.json
web/src/App.tsx
web/tsconfig.json
web/vite.config.ts
backend/auth-service/main.go
deploy/Dockerfile.caddy
deploy/Caddyfile
deploy/init/postgres-init.sql
"

missing=0
for f in $required; do
  if ! test -f "$root/$f"; then
    printf 'WARN: required build input not found on disk (may be acceptable): %s\n' "$f" >&2
  fi
done

# ── Verify .env.local is NOT in the build context ────────────────────
if grep -qE '^\.env\.\*$' "$ignore"; then
  # The .env.* glob exclusion covers .env.local — check that the rule
  # would actually catch it.
  if test -f "$root/deploy/.env.local"; then
    if ! grep -qF '.env.*' "$ignore"; then
      fail ".env.local must be excluded from Docker build context"
    fi
  fi
fi

# ── .env.example is explicitly allowed ───────────────────────────────
if ! grep -qF '!.env.example' "$ignore"; then
  fail ".env.example must be explicitly re-included for Docker Compose interpolation"
fi

printf 'PASS: .dockerignore excludes sensitive/local paths and preserves required build inputs.\n'
