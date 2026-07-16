#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
caddy="$root/deploy/Caddyfile"
compose="$root/deploy/docker-compose.yml"

grep -Fq 'forward_auth edge-identity:8090' "$caddy"
grep -Fq 'header_up X-IceQ-Edge-Client-IP {remote_host}' "$caddy"
grep -Fq 'copy_headers X-IceQ-RateLimit-Identity' "$caddy"
grep -Fq 'header_up -X-IceQ-Edge-Client-IP' "$caddy"
grep -Fq 'request_header -X-IceQ-RateLimit-Identity' "$caddy"
if grep -Fq 'header_up X-IceQ-RateLimit-Identity {remote_host}' "$caddy"; then
  echo 'raw remote_host reaches application identity header' >&2
  exit 1
fi
grep -Fq 'edge-identity:' "$compose"
grep -Fq 'ICEQ_EDGE_IDENTITY_HMAC_SECRET' "$compose"
if grep -A30 '^  edge-identity:' "$compose" | grep -Eq 'ports:|expose:'; then
  echo 'edge identity service must not be externally published' >&2
  exit 1
fi
