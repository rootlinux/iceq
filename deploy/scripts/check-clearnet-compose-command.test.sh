#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
check_script="$script_dir/check-clearnet-compose.sh"

if ! grep -Eq 'iceq/caddy:dev validate --config /etc/caddy/Caddyfile --adapter caddyfile' "$check_script"; then
  printf '%s\n' 'FAIL: Caddy image ENTRYPOINT must receive validate as its first argument.' >&2
  exit 1
fi

if grep -Eq 'iceq/caddy:dev caddy validate' "$check_script"; then
  printf '%s\n' 'FAIL: runtime command duplicates the Caddy ENTRYPOINT.' >&2
  exit 1
fi

printf '%s\n' 'PASS: Caddy runtime validation arguments respect the image ENTRYPOINT.'
