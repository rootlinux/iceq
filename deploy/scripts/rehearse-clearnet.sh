#!/bin/sh
set -eu

# Isolated local clearnet rehearsal runner.
#
# The caller must create a mode-0600 env file outside this repository and set:
#   ICEQ_REHEARSAL_ENV=/absolute/path/to/rehearsal.env
#
# Actions are intentionally closed: config validates without exposing resolved
# secrets, services prints the validated default service set, up starts a
# detached rehearsal, status inspects it, and down removes it only after this
# runner recorded a successful up. Successful up is never automatically torn
# down, so callers can exercise the stack before explicitly invoking down.

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
deploy_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
repo_root=$(CDPATH= cd -- "$deploy_dir/.." && pwd)
base="$deploy_dir/docker-compose.yml"
override="$deploy_dir/docker-compose.rehearsal.yml"
fixed_project=iceq-clearnet-rehearsal
state_root=${XDG_STATE_HOME:-${HOME:?HOME must be set}/.local/state}
state_dir="$state_root/iceq"
started_marker="$state_dir/$fixed_project.started"

usage() {
  printf '%s\n' "usage: ICEQ_REHEARSAL_ENV=/absolute/path/to/env $0 {config|services|up|down|status}" >&2
  exit 64
}

fail() {
  printf 'rehearsal refused: %s\n' "$1" >&2
  exit 1
}

[ "$#" -eq 1 ] || usage
action=$1
case "$action" in
  config|services|up|down|status) ;;
  *) usage ;;
esac

[ -z "${ICEQ_COMPOSE_PROJECT:-}" ] || fail "ICEQ_COMPOSE_PROJECT is managed by the runner"
[ -z "${ICEQ_ONION_LOCATION:-}" ] || fail "ICEQ_ONION_LOCATION must be empty"
[ -n "${ICEQ_REHEARSAL_ENV:-}" ] || fail "ICEQ_REHEARSAL_ENV is required"
case "$ICEQ_REHEARSAL_ENV" in
  /*) ;;
  *) fail "ICEQ_REHEARSAL_ENV must be absolute" ;;
esac
[ ! -L "$ICEQ_REHEARSAL_ENV" ] || fail "ICEQ_REHEARSAL_ENV must not be a symlink"
[ -f "$ICEQ_REHEARSAL_ENV" ] || fail "ICEQ_REHEARSAL_ENV must be a regular file"

env_dir=$(CDPATH= cd -- "$(dirname -- "$ICEQ_REHEARSAL_ENV")" && pwd -P)
env_path="$env_dir/$(basename -- "$ICEQ_REHEARSAL_ENV")"
case "$env_path" in
  "$repo_root"|"$repo_root"/*) fail "ICEQ_REHEARSAL_ENV must be outside the repository" ;;
esac

if mode=$(stat -f '%Lp' "$env_path" 2>/dev/null); then
  :
else
  mode=$(stat -c '%a' "$env_path" 2>/dev/null) || fail "cannot inspect ICEQ_REHEARSAL_ENV permissions"
fi
[ "$mode" = 600 ] || fail "ICEQ_REHEARSAL_ENV mode must be exactly 600"

config_json=$(mktemp "${TMPDIR:-/tmp}/iceq-clearnet-config.XXXXXX")
services_file=$(mktemp "${TMPDIR:-/tmp}/iceq-clearnet-services.XXXXXX")
up_in_progress=0
cleanup() {
  status=$?
  if [ "$up_in_progress" -eq 1 ]; then
    compose down >/dev/null 2>&1 || true
  fi
  rm -f -- "$config_json" "$services_file"
  return "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

compose() {
  ICEQ_ENV_FILE="$env_path" docker compose \
    --project-name "$fixed_project" \
    --env-file "$env_path" \
    -f "$base" \
    -f "$override" "$@"
}

compose config --services | LC_ALL=C sort > "$services_file"
compose config --format json > "$config_json"
python3 - "$config_json" "$services_file" "$fixed_project" <<'PY'
import json
import sys

config_path, services_path, project = sys.argv[1:]
with open(config_path, encoding="utf-8") as handle:
    config = json.load(handle)
with open(services_path, encoding="utf-8") as handle:
    service_names = [line.strip() for line in handle if line.strip()]

def require(condition, message):
    if not condition:
        raise SystemExit(f"rehearsal refused: {message}")

forbidden = {"tor", "caddy-tor"}
expected = {
    "auth-service", "caddy", "edge-identity", "file-service", "key-service",
    "message-service", "minio", "minio-init", "nats", "postgres",
    "presence-service", "redis", "scylla", "scylla-init", "ws-gateway",
}
require(set(service_names) == expected, "unexpected default service set")
require(forbidden.isdisjoint(service_names), "optional service leaked into default set")
require(config.get("name") == project, "unexpected Compose project")

services = config.get("services", {})
require(set(services) == expected, "resolved config contains unexpected services")
require(all("container_name" not in service for service in services.values()), "fixed container name found")
require(all(service.get("restart") == "no" for service in services.values()), "restart policy is not disabled")

ports = services["caddy"].get("ports", [])
observed = {
    (port.get("host_ip"), int(port.get("published")), int(port.get("target")), port.get("protocol"))
    for port in ports
}
required = {
    ("127.0.0.1", 8443, 443, "tcp"),
    ("127.0.0.1", 8443, 443, "udp"),
}
require(observed == required, "public bind escaped 127.0.0.1:8443")

networks = config.get("networks", {})
require(set(networks) == {"iceq-net"}, "unexpected rehearsal networks")
require(networks["iceq-net"].get("name") == f"{project}-net", "rehearsal network is not isolated")

volumes = config.get("volumes", {})
require("tor_keys" not in volumes, "optional persistent volume leaked into rehearsal")
for key, value in volumes.items():
    require(value.get("name") == f"{project}_{key}", f"volume {key} is not project-isolated")
PY

case "$action" in
  config)
    printf '%s\n' "validated project=$fixed_project bind=127.0.0.1:8443 network=$fixed_project-net"
    ;;
  services)
    cat "$services_file"
    ;;
  up)
    mkdir -p -- "$state_dir"
    chmod 700 "$state_dir"
    up_in_progress=1
    compose up --build --detach
    : > "$started_marker"
    chmod 600 "$started_marker"
    up_in_progress=0
    ;;
  down)
    [ -f "$started_marker" ] || fail "no successful runner-owned up is recorded"
    compose down
    rm -f -- "$started_marker"
    ;;
  status)
    compose ps
    ;;
esac
