#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
check_script="$script_dir/check-clearnet-compose.sh"

# The Caddy image ENTRYPOINT is "caddy", so the runtime command must
# invoke "caddy validate ..." — not bare "validate" (which Docker
# interprets as the executable to replace ENTRYPOINT with).
if ! grep -Eq 'iceq/caddy:dev caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile' "$check_script"; then
  printf '%s\n' 'FAIL: Caddy runtime validation must invoke caddy validate, not bare validate.' >&2
  exit 1
fi

# Bare 'validate' was a pre-existing defect: the image has no
# validate binary — Docker would try to run it as an entrypoint
# override and fail.
if grep -Eq 'iceq/caddy:dev[[:space:]]+validate[[:space:]]' "$check_script"; then
  printf '%s\n' 'FAIL: bare validate command detected — use caddy validate instead.' >&2
  exit 1
fi

# Both clearnet and Tor configs must be validated.
clearnet_count=$(grep -c 'caddy validate.*Caddyfile' "$check_script" || true)
if [ "$clearnet_count" -lt 2 ]; then
  printf '%s\n' 'FAIL: both clearnet and Tor Caddyfile configurations must be validated.' >&2
  exit 1
fi

printf '%s\n' 'PASS: Caddy runtime validation uses correct caddy validate invocation for both edge configs.'
