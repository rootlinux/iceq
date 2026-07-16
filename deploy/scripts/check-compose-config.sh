#!/bin/sh
set -eu

root=${ICEQ_PROJECT_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
temp_env=$(mktemp "${TMPDIR:-/tmp}/iceq-compose-env.XXXXXX")
child_pid=

cleanup() {
  if [ -n "$child_pid" ]; then
    kill "$child_pid" 2>/dev/null || true
    wait "$child_pid" 2>/dev/null || true
  fi
  rm -f -- "$temp_env"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

cp -- "$root/deploy/.env.example" "$temp_env"
ICEQ_ENV_FILE="$temp_env" docker compose --env-file "$temp_env" -f "$root/deploy/docker-compose.yml" config --quiet &
child_pid=$!
wait "$child_pid"
status=$?
child_pid=
exit "$status"
