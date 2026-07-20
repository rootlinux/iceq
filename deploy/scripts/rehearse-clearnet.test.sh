#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
deploy_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
repo_root=$(CDPATH= cd -- "$deploy_dir/.." && pwd)
runner="$script_dir/rehearse-clearnet.sh"
override="$deploy_dir/docker-compose.rehearsal.yml"
project=iceq-clearnet-rehearsal

scratch=$(mktemp -d "${TMPDIR:-/tmp}/iceq-clearnet-rehearsal-test.XXXXXX")
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT HUP INT TERM

env_file="$scratch/rehearsal.env"
cp -- "$deploy_dir/.env.example" "$env_file"
postgres_password="rehearsal-$(openssl rand -hex 16)"
redis_password="rehearsal-$(openssl rand -hex 16)"
minio_password="rehearsal-$(openssl rand -hex 16)"
jwt_secret=$(openssl rand -hex 32)
identity_secret=$(openssl rand -hex 32)
python3 - "$env_file" "$postgres_password" "$redis_password" "$minio_password" "$jwt_secret" "$identity_secret" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
postgres_password, redis_password, minio_password, jwt_secret, identity_secret = sys.argv[2:]
replacements = {
    "POSTGRES_PASSWORD": postgres_password,
    "ICEQ_PG_DSN": f"postgres://postgres:{postgres_password}@postgres:5432/iceq?sslmode=disable",
    "ICEQ_REDIS_PASSWORD": redis_password,
    "MINIO_ROOT_PASSWORD": minio_password,
    "ICEQ_JWT_SECRET": jwt_secret,
    "ICEQ_ALLOWED_ORIGINS": "https://127.0.0.1:8443",
    "ICEQ_EDGE_IDENTITY_HMAC_SECRET": identity_secret,
}
seen = set()
rewritten = []
for line in path.read_text(encoding="utf-8").splitlines():
    key, separator, _ = line.partition("=")
    if separator and key in replacements:
        rewritten.append(f"{key}={replacements[key]}")
        seen.add(key)
    else:
        rewritten.append(line)

if seen != set(replacements):
    raise SystemExit(f"missing env placeholders: {sorted(set(replacements) - seen)}")
path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
PY
cat >> "$env_file" <<EOF
ICEQ_HTTPS_BIND=127.0.0.1:8443
ICEQ_HTTPS_UDP_BIND=127.0.0.1:8443
EOF
chmod 600 "$env_file"

test -x "$runner"
test -f "$override"

if grep -F -- '--profile tor' "$runner" >/dev/null; then
  printf '%s\n' 'runner must not enable optional profiles' >&2
  exit 1
fi
if grep -F -- '.env.local' "$runner" >/dev/null; then
  printf '%s\n' 'runner must not read the production env file' >&2
  exit 1
fi
grep -Fq 'ICEQ_REHEARSAL_ENV' "$runner"
grep -Fq -- '--project-name "$fixed_project"' "$runner"

compose() {
  ICEQ_ENV_FILE="$env_file" docker compose \
    --project-name "$project" \
    --env-file "$env_file" \
    -f "$deploy_dir/docker-compose.yml" \
    -f "$override" "$@"
}

expected_services='auth-service
caddy
edge-identity
file-service
key-service
message-service
minio
minio-init
nats
postgres
presence-service
redis
scylla
scylla-init
ws-gateway'
resolved_services=$(compose config --services | LC_ALL=C sort)
test "$resolved_services" = "$expected_services"

config_json="$scratch/config.json"
compose config --format json > "$config_json"
python3 - "$config_json" "$project" <<'PY'
import json
import sys

path, project = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    config = json.load(handle)

assert config["name"] == project, config["name"]
services = config["services"]
assert all("container_name" not in service for service in services.values())
assert all(service.get("restart") == "no" for service in services.values())

ports = services["caddy"]["ports"]
observed = {(p["host_ip"], int(p["published"]), int(p["target"]), p["protocol"]) for p in ports}
assert observed == {
    ("127.0.0.1", 8443, 443, "tcp"),
    ("127.0.0.1", 8443, 443, "udp"),
}, observed

networks = config["networks"]
assert set(networks) == {"iceq-net"}, networks
network_name = networks["iceq-net"]["name"]
assert network_name == f"{project}-net", network_name

volumes = config["volumes"]
assert "tor_keys" not in volumes, volumes
for key, value in volumes.items():
    expected = f"{project}_{key}"
    assert value["name"] == expected, (key, value["name"], expected)
PY

ICEQ_REHEARSAL_ENV="$env_file" "$runner" services > "$scratch/runner-services"
test "$(LC_ALL=C sort "$scratch/runner-services")" = "$expected_services"
ICEQ_REHEARSAL_ENV="$env_file" "$runner" config > "$scratch/runner-config"

mkdir -p "$scratch/bin" "$scratch/state"
cat > "$scratch/bin/docker" <<'EOF'
#!/bin/sh
set -eu

case " $* " in
  *' config --services '*)
    printf '%s\n' 'auth-service' 'caddy' 'edge-identity' 'file-service' 'key-service' 'message-service' 'minio' 'minio-init' 'nats' 'postgres' 'presence-service' 'redis' 'scylla' 'scylla-init' 'ws-gateway'
    ;;
  *' config --format json '*)
    cat "$ICEQ_TEST_CONFIG"
    ;;
  *' up --build --detach '*)
    printf '%s\n' up >> "$ICEQ_TEST_LOG"
    if [ "${ICEQ_TEST_UP_SUCCESS:-}" = 1 ]; then
      exit 0
    fi
    exit 1
    ;;
  *' down '*)
    printf '%s\n' down >> "$ICEQ_TEST_LOG"
    ;;
  *)
    printf 'unexpected docker arguments: %s\n' "$*" >&2
    exit 64
    ;;
esac
EOF
chmod 755 "$scratch/bin/docker"
: > "$scratch/docker.log"
if PATH="$scratch/bin:$PATH" ICEQ_TEST_CONFIG="$config_json" ICEQ_TEST_LOG="$scratch/docker.log" XDG_STATE_HOME="$scratch/state" ICEQ_REHEARSAL_ENV="$env_file" "$runner" up >/dev/null 2>&1; then
  printf '%s\n' 'runner accepted a failed up' >&2
  exit 1
fi
test "$(cat "$scratch/docker.log")" = 'up
down'

: > "$scratch/docker.log"
PATH="$scratch/bin:$PATH" ICEQ_TEST_CONFIG="$config_json" ICEQ_TEST_LOG="$scratch/docker.log" ICEQ_TEST_UP_SUCCESS=1 XDG_STATE_HOME="$scratch/state" ICEQ_REHEARSAL_ENV="$env_file" "$runner" up
test "$(cat "$scratch/docker.log")" = up
test -f "$scratch/state/iceq/$project.started"
PATH="$scratch/bin:$PATH" ICEQ_TEST_CONFIG="$config_json" ICEQ_TEST_LOG="$scratch/docker.log" XDG_STATE_HOME="$scratch/state" ICEQ_REHEARSAL_ENV="$env_file" "$runner" down
test "$(cat "$scratch/docker.log")" = 'up
down'
test ! -e "$scratch/state/iceq/$project.started"

if ICEQ_ONION_LOCATION=https://example.invalid ICEQ_REHEARSAL_ENV="$env_file" "$runner" services >/dev/null 2>&1; then
  printf '%s\n' 'runner accepted an onion location' >&2
  exit 1
fi
if ICEQ_COMPOSE_PROJECT=wrong ICEQ_REHEARSAL_ENV="$env_file" "$runner" services >/dev/null 2>&1; then
  printf '%s\n' 'runner accepted a caller-provided project name' >&2
  exit 1
fi
ln -s "$env_file" "$scratch/symlink.env"
if ICEQ_REHEARSAL_ENV="$scratch/symlink.env" "$runner" services >/dev/null 2>&1; then
  printf '%s\n' 'runner accepted a symlink env file' >&2
  exit 1
fi
chmod 640 "$env_file"
if ICEQ_REHEARSAL_ENV="$env_file" "$runner" services >/dev/null 2>&1; then
  printf '%s\n' 'runner accepted an env file without mode 600' >&2
  exit 1
fi

printf 'resolved default services: %s\n' "$(printf '%s' "$resolved_services" | tr '\n' ' ')"
printf '%s\n' 'resolved public binds: 127.0.0.1:8443->443/tcp, 127.0.0.1:8443->443/udp'
printf 'resolved network: %s-net\n' "$project"
printf '%s\n' 'clearnet rehearsal contract: PASS'
