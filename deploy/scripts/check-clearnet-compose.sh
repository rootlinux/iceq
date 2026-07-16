#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
compose_file="$repo_root/deploy/docker-compose.yml"
caddyfile="$repo_root/deploy/Caddyfile"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

compose_services() {
  docker compose -f "$compose_file" "$@" config --services
}

default_services=$(compose_services)
tor_services=$(compose_services --profile tor)

printf '%s\n' "$default_services" | grep -qx tor &&
  fail "default Compose configuration must exclude the Tor service"
printf '%s\n' "$tor_services" | grep -qx tor ||
  fail "the tor profile must include the Tor service"

default_config=$(docker compose -f "$compose_file" config)
printf '%s\n' "$default_config" | grep -Eq '^[[:space:]]+tor:$' &&
  fail "default resolved Compose configuration contains the Tor service"
printf '%s\n' "$default_config" | grep -Eq 'condition:.*tor|tor:.*condition' &&
  fail "a default service depends on Tor"

grep -Eq '^iceq\.space, www\.iceq\.space \{' "$caddyfile" ||
  fail "Caddyfile must expose the iceq.space clearnet hosts"
grep -Eq "@hasOnionLocation expression .*ICEQ_ONION_LOCATION.*!= ''" "$caddyfile" ||
  fail "Onion-Location must be guarded by a non-empty environment variable"
grep -Eq 'header @hasOnionLocation Onion-Location "\{\$ICEQ_ONION_LOCATION\}"' "$caddyfile" ||
  fail "guarded Onion-Location response header is missing"

for route in '/api/auth/' '/api/contacts/' '/api/keys/' '/api/messages/' '/api/groups' '/api/presence/' '/api/files/' '/ws'; do
  grep -Fq "$route" "$caddyfile" || fail "Caddy route is missing: $route"
done

for header in Strict-Transport-Security Content-Security-Policy X-Content-Type-Options X-Frame-Options Referrer-Policy Permissions-Policy; do
  grep -Fq "$header" "$caddyfile" || fail "Caddy security header is missing: $header"
done

printf 'PASS: default Compose is clearnet-only; Tor is opt-in and Caddy clearnet policy is present.\n'
