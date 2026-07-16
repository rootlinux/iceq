#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
checker="$script_dir/check-compose-config.sh"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/iceq-compose-check-test.XXXXXX")
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT HUP INT TERM

project="$scratch/project"
mkdir -p "$project/deploy" "$scratch/bin" "$scratch/tmp"
cp -- "$script_dir/../.env.example" "$project/deploy/.env.example"
cp -- "$script_dir/../docker-compose.yml" "$project/deploy/docker-compose.yml"

cat > "$scratch/bin/docker" <<'EOF'
#!/bin/sh
set -eu
test -n "${ICEQ_ENV_FILE:-}"
test -f "$ICEQ_ENV_FILE"
printf '%s\n' "$ICEQ_ENV_FILE" >> "$ICEQ_TEST_LOG"
if [ "${ICEQ_TEST_SLEEP:-0}" -gt 0 ]; then sleep "$ICEQ_TEST_SLEEP"; fi
EOF
chmod +x "$scratch/bin/docker"

export PATH="$scratch/bin:$PATH"
export ICEQ_PROJECT_ROOT="$project"
export ICEQ_TEST_LOG="$scratch/docker.log"
export TMPDIR="$scratch/tmp"

# A pre-existing production env is byte-identical after validation.
printf '%s\n' 'ICEQ_TEST_SECRET=preserve-me' > "$project/deploy/.env.local"
before=$(cksum "$project/deploy/.env.local")
"$checker"
test "$before" = "$(cksum "$project/deploy/.env.local")"

# An absent production env remains absent; a later real file is never removed.
rm -- "$project/deploy/.env.local"
"$checker"
test ! -e "$project/deploy/.env.local"
printf '%s\n' 'ICEQ_TEST_SECRET=replacement' > "$project/deploy/.env.local"
"$checker"
grep -Fq 'ICEQ_TEST_SECRET=replacement' "$project/deploy/.env.local"

# Concurrent checks use distinct temporary env paths and clean both.
: > "$ICEQ_TEST_LOG"
"$checker" & first=$!
"$checker" & second=$!
wait "$first"
wait "$second"
test "$(sort -u "$ICEQ_TEST_LOG" | wc -l | tr -d ' ')" -eq 2
while IFS= read -r path; do test ! -e "$path"; done < "$ICEQ_TEST_LOG"

# TERM cleans the owned temporary env while leaving the production env intact.
: > "$ICEQ_TEST_LOG"
ICEQ_TEST_SLEEP=30 "$checker" & interrupted=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  test -s "$ICEQ_TEST_LOG" && break
  sleep 0.1
done
temp_path=$(sed -n '1p' "$ICEQ_TEST_LOG")
test -n "$temp_path"
test -f "$temp_path"
kill -TERM "$interrupted"
wait "$interrupted" 2>/dev/null || true
test ! -e "$temp_path"
grep -Fq 'ICEQ_TEST_SECRET=replacement' "$project/deploy/.env.local"

printf '%s\n' 'compose config behavior: PASS'
