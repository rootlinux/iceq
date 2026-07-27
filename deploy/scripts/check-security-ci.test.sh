#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
workflow="$root/.github/workflows/security-ci.yml"
compose_check="$root/deploy/scripts/check-compose-config.sh"

test -x "$compose_check"
grep -Fq 'mktemp' "$compose_check"
grep -Fq 'trap ' "$compose_check"
grep -Fq -- '--env-file "$temp_env"' "$compose_check"
! grep -Fq 'cp deploy/.env.example deploy/.env.local' "$workflow"
grep -Fq './deploy/scripts/check-compose-config.sh' "$workflow"
grep -Fq './deploy/scripts/check-compose-config.test.sh' "$workflow"
grep -Fq './deploy/scripts/check-security-ci.test.sh' "$workflow"
grep -Eq '^[[:space:]]+run: node --import tsx scripts/audit-policy\.mts$' "$workflow"
grep -Eq '^[[:space:]]+run: node --import tsx scripts/audit-policy\.mts --production$' "$workflow"
grep -Fq './deploy/scripts/check-clearnet-compose-command.test.sh' "$workflow"
grep -Eq '^[[:space:]]+ICEQ_ENV_FILE=\.env\.example ./deploy/scripts/check-clearnet-compose\.sh$' "$workflow"

! grep -Fq 'gitleaks/gitleaks-action@' "$workflow"
grep -Fq 'GITLEAKS_VERSION: 8.24.3' "$workflow"
grep -Eq 'GITLEAKS_SHA256: [0-9a-f]{64}$' "$workflow"
grep -Fq 'sha256sum -c -' "$workflow"
grep -Fq 'gitleaks detect --source . --redact --no-banner' "$workflow"

printf '%s\n' 'security CI source contract: PASS'
