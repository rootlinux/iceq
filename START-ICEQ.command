#!/bin/zsh
set -euo pipefail

export PATH="${PATH:-/usr/bin:/bin}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

repo_root=${0:A:h}
runner=${ICEQ_RUNNER:-"$repo_root/deploy/scripts/rehearse-clearnet.sh"}
env_file=${ICEQ_REHEARSAL_ENV:-"$HOME/Library/Application Support/IceQ/rehearsal.env"}
local_url=${ICEQ_LOCAL_URL:-"https://localhost:8443"}
project=iceq-clearnet-rehearsal
expected_healthy=13
start_timeout=${ICEQ_START_TIMEOUT_SECONDS:-300}

fail() {
  print -u2 -- "IceQ could not start: $1"
  if [[ -z ${ICEQ_NONINTERACTIVE:-} ]]; then
    osascript -e 'display notification "IceQ could not start. Check the Terminal window." with title "IceQ"' >/dev/null 2>&1 || true
    print -u2 -- "Press any key to close this window."
    read -k 1 -s || true
  fi
  exit 1
}

[[ -x "$runner" ]] || fail "rehearsal runner is missing: $runner"
[[ -f "$env_file" && ! -L "$env_file" ]] || fail "protected environment file is missing: $env_file"

stack_healthy() {
  local healthy_count
  healthy_count=$(docker ps \
    --filter "label=com.docker.compose.project=$project" \
    --filter health=healthy \
    --format '{{.ID}}' | wc -l | tr -d '[:space:]')
  [[ "$healthy_count" == "$expected_healthy" ]] && curl -skSf "$local_url/login" >/dev/null
}

if ! docker info >/dev/null 2>&1; then
  print -- "Starting Docker Desktop..."
  open -a Docker || fail "Docker Desktop could not be opened"
  deadline=$((SECONDS + start_timeout))
  until docker info >/dev/null 2>&1; do
    (( SECONDS < deadline )) || fail "Docker Desktop did not become ready in ${start_timeout}s"
    sleep 2
  done
fi

if ! stack_healthy; then
  print -- "Starting the isolated IceQ stack..."
  ICEQ_REHEARSAL_ENV="$env_file" "$runner" up || fail "Docker Compose startup failed"

  deadline=$((SECONDS + start_timeout))
  until stack_healthy; do
    (( SECONDS < deadline )) || fail "all IceQ services did not become healthy in ${start_timeout}s"
    sleep 2
  done
else
  print -- "IceQ is already running."
fi

print -- "IceQ is ready: $local_url"
if [[ -z ${ICEQ_NO_BROWSER:-} ]]; then
  open "$local_url"
fi
if [[ -z ${ICEQ_NONINTERACTIVE:-} ]]; then
  osascript -e 'display notification "All services are healthy." with title "IceQ is ready"' >/dev/null 2>&1 || true
fi

