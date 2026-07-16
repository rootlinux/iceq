#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
temp_env=$(mktemp "${TMPDIR:-/tmp}/iceq-compose-env.XXXXXX")
created_local_env=0

cleanup() {
  if [ "$created_local_env" -eq 1 ]; then
    rm -f -- "$root/deploy/.env.local"
  fi
  rm -f -- "$temp_env"
}
trap cleanup EXIT HUP INT TERM

cp -- "$root/deploy/.env.example" "$temp_env"
if [ ! -e "$root/deploy/.env.local" ]; then
  ln -s -- "$temp_env" "$root/deploy/.env.local"
  created_local_env=1
fi

docker compose --env-file "$temp_env" -f "$root/deploy/docker-compose.yml" config --quiet
