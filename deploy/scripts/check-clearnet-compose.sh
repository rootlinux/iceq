#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
compose_file="$repo_root/deploy/docker-compose.yml"
caddyfile="$repo_root/deploy/Caddyfile"
tor_caddyfile="$repo_root/deploy/Caddyfile.tor"
onion_script="$repo_root/deploy/scripts/onion-address.sh"

# Compose interpolates required service environment before env_file is loaded.
# Static validation uses a non-secret fixture and never starts the signer.
export ICEQ_EDGE_IDENTITY_HMAC_SECRET=${ICEQ_EDGE_IDENTITY_HMAC_SECRET:-01234567890123456789012345678901}

# Honour ICEQ_ENV_FILE (CI supplies .env.example so docker compose can
# resolve required variables like ICEQ_NATS_TOKEN).
# ICEQ_ENV_FILE is interpreted relative to the Compose project directory
# (deploy/) because it is also interpolated into env_file: directives.
# The --env-file flag always receives the absolute path.
if [ -n "${ICEQ_ENV_FILE:-}" ]; then
  case "$ICEQ_ENV_FILE" in
    /*) env_file_flag="--env-file $ICEQ_ENV_FILE" ;;
    *)  env_file_flag="--env-file $repo_root/deploy/$ICEQ_ENV_FILE" ;;
  esac
else
  env_file_flag=""
fi

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

compose_services() {
  # shellcheck disable=SC2086
  docker compose -f "$compose_file" $env_file_flag "$@" config --services
}

default_services=$(compose_services)
tor_services=$(compose_services --profile tor)

printf '%s\n' "$default_services" | grep -qx tor &&
  fail "default Compose configuration must exclude the Tor service"
printf '%s\n' "$tor_services" | grep -qx tor ||
  fail "the tor profile must include the Tor service"
printf '%s\n' "$default_services" | grep -qx caddy-tor &&
  fail "default Compose configuration must exclude the Tor edge"
printf '%s\n' "$tor_services" | grep -qx caddy-tor ||
  fail "the tor profile must include the isolated Tor edge"

default_config=$(docker compose -f "$compose_file" $env_file_flag config)
printf '%s\n' "$default_config" | grep -Eq '^[[:space:]]+tor:$' &&
  fail "default resolved Compose configuration contains the Tor service"
printf '%s\n' "$default_config" | grep -Eq 'condition:.*tor|tor:.*condition' &&
  fail "a default service depends on Tor"

grep -Eq '^:80[[:space:]]*\{' "$caddyfile" &&
  fail "default Caddyfile must not load the Tor-only :80 listener"
test -f "$tor_caddyfile" || fail "isolated Tor edge Caddyfile is missing"
grep -Eq '^:80[[:space:]]*\{' "$tor_caddyfile" ||
  fail "isolated Tor edge must own the internal :80 listener"
grep -Fq 'reverse_proxy https://caddy:443' "$tor_caddyfile" ||
  fail "isolated Tor edge must forward to the shared clearnet policy edge"
grep -Fq 'header_up Host iceq.space' "$tor_caddyfile" ||
  fail "isolated Tor edge must select the iceq.space Caddy site"
if grep -Fq 'tls_insecure_skip_verify' "$tor_caddyfile"; then
  fail "isolated Tor edge must verify the default Caddy TLS certificate"
fi
grep -Fq 'tls_server_name iceq.space' "$tor_caddyfile" ||
  fail "isolated Tor edge must verify TLS for iceq.space"
grep -Fq 'ICECQ_TOR_SERVICE_HOSTS=80:caddy-tor:80' "$compose_file" ||
  fail "Tor hidden service must target only the isolated Tor edge"
grep -Fq 'http://127.0.0.1:80/health' "$compose_file" ||
  fail "Tor edge healthcheck must exercise the proxied upstream /health route"
if grep -Fq '/edge-health' "$compose_file" "$tor_caddyfile"; then
  fail "Tor edge must not use a synthetic local-only health endpoint"
fi

clearnet_site=$(sed -n '/^iceq\.space, www\.iceq\.space {$/,/^}$/p' "$caddyfile")
route_snippet=$(sed -n '/^(iceq_routes) {$/,/^# ── Public TLS listener/p' "$caddyfile")
security_snippet=$(sed -n '/^(security_headers) {$/,/^# ── Upstream forwarding headers/p' "$caddyfile")

printf '%s\n' "$clearnet_site" | grep -Eq '^iceq\.space, www\.iceq\.space \{' ||
  fail "Caddyfile must expose the iceq.space clearnet hosts"
printf '%s\n' "$clearnet_site" | grep -Fq 'import iceq_routes' ||
  fail "the clearnet hosts must import the shared IceQ route snippet"
printf '%s\n' "$clearnet_site" | grep -Eq "@hasOnionLocation expression .*ICEQ_ONION_LOCATION.*!= ''" ||
  fail "Onion-Location must be guarded by a non-empty environment variable"
printf '%s\n' "$clearnet_site" | grep -Eq 'header @hasOnionLocation Onion-Location "\{\$ICEQ_ONION_LOCATION\}"' ||
  fail "guarded Onion-Location response header is missing"
if printf '%s\n' "$clearnet_site" | grep -Eq '^[[:space:]]*header[[:space:]]+Onion-Location'; then
  fail "clearnet must not contain an unguarded Onion-Location directive"
fi

for route in '/api/auth/' '/api/contacts/' '/api/keys/' '/api/messages/' '/api/groups' '/api/presence/' '/api/files/' '/ws'; do
  printf '%s\n' "$route_snippet" | grep -Fq "$route" ||
    fail "shared Caddy route snippet is missing: $route"
done

for header in Strict-Transport-Security Content-Security-Policy X-Content-Type-Options X-Frame-Options Referrer-Policy Permissions-Policy; do
  printf '%s\n' "$security_snippet" | grep -Fq "$header" ||
    fail "shared Caddy security snippet is missing: $header"
done

printf '%s\n' "$route_snippet" | grep -Fq 'import security_headers' ||
  fail "shared routes must import the shared security-header snippet"

grep -Eq 'docker compose .*--profile tor .*logs tor' "$onion_script" ||
  fail "Tor diagnostic command must explicitly enable the tor profile"

if docker image inspect iceq/caddy:dev >/dev/null 2>&1; then
  docker run --rm \
    -e ICEQ_ONION_LOCATION= \
    -v "$caddyfile:/etc/caddy/Caddyfile:ro" \
    iceq/caddy:dev caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null ||
    fail "Caddy failed to validate the clearnet configuration"
  docker run --rm \
    -v "$tor_caddyfile:/etc/caddy/Caddyfile:ro" \
    iceq/caddy:dev caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null ||
    fail "Caddy failed to validate the isolated Tor-edge configuration"
  printf 'PASS: Caddy runtime syntax validation completed for both edge configurations.\n'
else
  printf 'SKIP: iceq/caddy:dev is unavailable; runtime Caddy validation was not performed.\n'
fi

printf 'STATIC PASS: default Compose is clearnet-only; Tor edge isolation and Caddy policy are structurally valid.\n'
