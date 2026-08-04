#!/bin/zsh
set -euo pipefail

export PATH="${PATH:-/usr/bin:/bin}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

repo_root=${0:A:h}
runner=${ICEQ_RUNNER:-"$repo_root/deploy/scripts/rehearse-clearnet.sh"}
env_file=${ICEQ_REHEARSAL_ENV:-"$HOME/Library/Application Support/IceQ/rehearsal.env"}
project=iceq-clearnet-rehearsal
stop_timeout=${ICEQ_STOP_TIMEOUT_SECONDS:-60}

fail() {
  print -u2 -- "IceQ could not stop: $1"
  if [[ -z ${ICEQ_NONINTERACTIVE:-} ]]; then
    osascript -e 'display notification "IceQ could not stop. Check the Terminal window." with title "IceQ"' >/dev/null 2>&1 || true
    print -u2 -- "Press any key to close this window."
    read -k 1 -s || true
  fi
  exit 1
}

container_count() {
  docker ps -a \
    --filter "label=com.docker.compose.project=$project" \
    --format '{{.ID}}' | wc -l | tr -d '[:space:]'
}

if ! docker info >/dev/null 2>&1; then
  fail "Docker Desktop is not running"
fi

if [[ "$(container_count)" == "0" ]]; then
  print -- "IceQ is already stopped. Persistent data is unchanged."
  exit 0
fi

[[ -x "$runner" ]] || fail "rehearsal runner is missing: $runner"
[[ -f "$env_file" && ! -L "$env_file" ]] || fail "protected environment file is missing: $env_file"

print -- "Stopping IceQ without deleting persistent data..."
ICEQ_REHEARSAL_ENV="$env_file" "$runner" down || fail "Docker Compose shutdown failed"

deadline=$((SECONDS + stop_timeout))
while [[ "$(container_count)" != "0" ]]; do
  (( SECONDS < deadline )) || fail "IceQ containers remained after ${stop_timeout}s"
  sleep 1
done

print -- "IceQ stopped. PostgreSQL, Redis, ScyllaDB, NATS, MinIO, and Caddy data were preserved."
if [[ -z ${ICEQ_NONINTERACTIVE:-} ]]; then
  osascript -e 'display notification "Persistent data was preserved." with title "IceQ stopped"' >/dev/null 2>&1 || true
fi
