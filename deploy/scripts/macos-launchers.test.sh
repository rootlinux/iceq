#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
start_launcher="$repo_root/START-ICEQ.command"
stop_launcher="$repo_root/STOP-ICEQ.command"

fail() {
  printf 'macOS launcher test failed: %s\n' "$1" >&2
  exit 1
}

[ -x "$start_launcher" ] || fail "START-ICEQ.command is missing or not executable"
[ -x "$stop_launcher" ] || fail "STOP-ICEQ.command is missing or not executable"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/iceq-macos-launchers.XXXXXX")
cleanup() {
  rm -rf -- "$scratch"
}
trap cleanup EXIT HUP INT TERM

fake_bin="$scratch/bin"
test_home="$scratch/home"
test_state="$scratch/stack-running"
test_log="$scratch/calls.log"
runner="$scratch/rehearsal-runner"
env_file="$scratch/rehearsal.env"
mkdir -p -- "$fake_bin" "$test_home"
: > "$env_file"
chmod 600 "$env_file"

cat > "$fake_bin/docker" <<'SH'
#!/bin/sh
printf 'docker %s\n' "$*" >> "$ICEQ_TEST_LOG"
case "${1:-}" in
  info)
    exit 0
    ;;
  ps)
    if [ -f "$ICEQ_TEST_STATE" ]; then
      index=1
      while [ "$index" -le 13 ]; do
        printf 'healthy-%s\n' "$index"
        index=$((index + 1))
      done
    fi
    exit 0
    ;;
esac
exit 0
SH

cat > "$fake_bin/curl" <<'SH'
#!/bin/sh
printf 'curl %s\n' "$*" >> "$ICEQ_TEST_LOG"
[ -f "$ICEQ_TEST_STATE" ]
SH

cat > "$fake_bin/open" <<'SH'
#!/bin/sh
printf 'open %s\n' "$*" >> "$ICEQ_TEST_LOG"
SH

cat > "$fake_bin/osascript" <<'SH'
#!/bin/sh
printf 'osascript %s\n' "$*" >> "$ICEQ_TEST_LOG"
SH

cat > "$runner" <<'SH'
#!/bin/sh
printf 'runner %s\n' "$*" >> "$ICEQ_TEST_LOG"
case "${1:-}" in
  up)
    : > "$ICEQ_TEST_STATE"
    ;;
  down)
    rm -f -- "$ICEQ_TEST_STATE"
    ;;
  *)
    exit 64
    ;;
esac
SH
chmod +x "$fake_bin/docker" "$fake_bin/curl" "$fake_bin/open" "$fake_bin/osascript" "$runner"

run_launcher() {
  PATH="$fake_bin:/usr/bin:/bin" \
  HOME="$test_home" \
  ICEQ_REHEARSAL_ENV="$env_file" \
  ICEQ_RUNNER="$runner" \
  ICEQ_TEST_LOG="$test_log" \
  ICEQ_TEST_STATE="$test_state" \
  ICEQ_START_TIMEOUT_SECONDS=3 \
  ICEQ_NONINTERACTIVE=1 \
  "$@"
}

# A cold start must invoke the guarded rehearsal runner, wait for all thirteen
# healthy services, and open the local HTTPS endpoint.
: > "$test_log"
run_launcher "$start_launcher"
grep -Fxq 'runner up' "$test_log" || fail "cold start did not invoke rehearsal up"
grep -Fxq 'open https://localhost:8443' "$test_log" || fail "cold start did not open the IceQ URL"
[ -f "$test_state" ] || fail "cold start did not reach a running state"

# Starting an already healthy stack must be idempotent and must not rebuild it.
: > "$test_log"
run_launcher "$start_launcher"
if grep -Fq 'runner up' "$test_log"; then
  fail "healthy stack was started a second time"
fi
grep -Fxq 'open https://localhost:8443' "$test_log" || fail "warm start did not open the IceQ URL"

# Stop must use the guarded runner and preserve volumes by never issuing a
# direct Docker volume deletion or a down -v command.
: > "$test_log"
run_launcher "$stop_launcher"
grep -Fxq 'runner down' "$test_log" || fail "stop did not invoke rehearsal down"
[ ! -f "$test_state" ] || fail "stop left the stack running"
if grep -Eq 'volume|down .*-[^-]*v|down --volumes' "$test_log"; then
  fail "stop attempted to delete persistent data"
fi

# A missing protected environment file must fail before Docker or the runner is
# touched, rather than silently falling back to repository secrets.
rm -f -- "$env_file"
: > "$test_log"
if run_launcher "$start_launcher" >/dev/null 2>&1; then
  fail "start accepted a missing rehearsal environment"
fi
[ ! -s "$test_log" ] || fail "missing environment touched Docker or the runner"

printf '%s\n' 'macOS one-click launchers: PASS'
