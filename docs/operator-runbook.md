# IceQ Operator Runbook

This runbook describes production operations without placing secret values in shell history, process arguments, logs, commits, or tickets. Replace placeholders interactively in a permission-restricted `deploy/.env.local`; never paste real values into commands or CI output.

## 1. Secrets and storage

Copy `deploy/.env.example` to `deploy/.env.local`, set mode `0600`, and generate every password with a cryptographically secure password manager. Generate the JWT secret exactly as the template documents, capture it directly into the protected secret store/editor, and do not echo it. Keep an encrypted offline recovery copy with tested access controls.

Rotating database, Redis, NATS, or MinIO credentials requires coordinated service configuration and credential changes. Redis (`ICEQ_REDIS_PASSWORD`) and NATS (`ICEQ_NATS_TOKEN`) are enforced at server startup through `requirepass` and `--auth` respectively. Services fail fast when `ICEQ_REDIS_REQUIRE_AUTH=1` and the password is empty. Credential rotation must update the protected env file, restart Redis/NATS to pick up the new server-side credential, then restart all consuming services in dependency order. Rotate the JWT secret only during a planned global logout: existing access and refresh tokens will fail verification. Take and verify backups first, stage new credentials without printing them, restart affected services in dependency order, and verify login/refresh plus revoked-old-session behavior. Remove old credentials only after validation.

Docker named volumes are not encrypted by this repository. Full-disk/volume encryption, encrypted snapshots, backup encryption, key custody, and secure media disposal are operator responsibilities.

## 2. Clearnet-first release gate

Keep Tor disabled. Validate with `./deploy/scripts/check-compose-config.sh`; it uses a temporary non-secret interpolation file and never overwrites an existing `deploy/.env.local`. Run all gates in `docs/security-status.md`, back up every stateful volume/database, compare the recorded migration ledger and live schema with `deploy/init/migrations/`, apply only missing migrations in numeric order, verify schema, then deploy the clearnet stack. Confirm HTTPS/WSS, headers, auth lifecycle, messaging, groups, files, disappearing messages, and panic-wipe behavior with dedicated test accounts. Inspect minimized logs for errors without collecting credentials, tokens, private keys, plaintext, raw IPs, User-Agent, or ciphertext-bearing URLs.

Do not enable Tor until clearnet real-user acceptance is explicitly complete. Later Tor opt-in uses `--profile tor`; retrieve the local onion hostname with `deploy/scripts/onion-address.sh`, test external publication/reachability separately, and only then configure `ICEQ_ONION_LOCATION`. Back up the entire `tor_keys` volume directly into encrypted offline storage without displaying or extracting private-key contents. A restore test must reproduce the same onion hostname before the service is advertised.

## 3. Backups, migrations, and restore tests

Back up PostgreSQL, ScyllaDB, Redis/NATS state required by the chosen delivery objectives, MinIO objects, Caddy state, protected configuration, and—only after Tor approval—the `tor_keys` volume. Database-native consistent snapshots/dumps are preferred over copying live volume files. Record image Git SHA, schema versions, backup time, retention, and integrity hash; never record secrets.

Before migration, stop or drain writers as required by the migration, take an encrypted backup, record current migration/schema state, and apply each missing migration in numeric order. Migrations 014–017 are additive and guarded with `IF NOT EXISTS` or `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`; this is retry-safe for new columns but does not verify an existing object's definition — record success and run the explicit schema checks. Migration 016 (`wipe_jobs`) creates a durable job table the auth-service background worker depends on; the worker fails closed if the table is absent. Existing-volume prerequisites are in `README.md`; Docker init mounts do not migrate existing databases. Fail closed if required tables/columns are absent.

ScyllaDB `--developer-mode` defaults to `0` in production Compose (controlled by `ICEQ_SCYLLA_DEVELOPER_MODE`). Do not enable developer mode on production volumes; it disables memory and disk safety checks. Acceptance/staging may use `1` only on explicitly disposable volumes.

A backup is not accepted until restored into an isolated environment and tested for schema presence, representative auth/contact/group metadata, ciphertext/object linkage, service startup, and a harmless test-user round trip. Never run restore tests against production endpoints or reuse production credentials.

## 4. Logging and no-log checks

Verify Caddy’s configured field deletion and `log_skip` routes in `deploy/Caddyfile`, then sample live edge and application logs using test traffic. Search for Authorization/Cookie values, JWT-like strings, private-key markers, message plaintext, raw client IP/User-Agent, usernames/UINs, object URLs, and request bodies. Treat any occurrence as an incident; preserve only the minimum redacted evidence. Docker JSON logs are size-rotated, not “no logs”; backend operational logs and infrastructure telemetry still require periodic review and retention limits.

## 5. Panic wipe and incidents

Panic wipe is destructive and cannot recall data already delivered or backed up. Test only with disposable accounts. Before enabling it for users, verify migrations `004` and `005`, durable revocation, expired/revoked session rejection, key/contact/group removal, and bounded ciphertext cleanup. Never promise deletion from peer devices or immutable backups.

For an incident: contain access, preserve minimized/redacted evidence, rotate affected credentials, revoke sessions or bump epochs, assess malicious web/dependency exposure, and notify users of the precise affected guarantees. If identity or sender keys may be compromised, require fresh keys and out-of-band safety verification. If storage was exposed, assume metadata and ciphertext exposure even though plaintext is client-encrypted. Document timeline, scope, decisions, and follow-up without copying secrets or private user content.

## 6. Updates and rollback

Review Go/npm advisories and container upstream releases regularly. Run the pinned CI gates, inspect lockfile/image changes, and test migrations plus restore in staging. Container tags in Compose are not all digest-pinned, so record resolved image digests for each release.

Rollback means restoring the previously recorded compatible images/configuration and, when necessary, the pre-migration encrypted backups. Prefer backward-compatible additive migrations; do not improvise destructive schema rollback after new writes. Stop writers, assess compatibility, restore as an isolated rehearsal, then execute the approved rollback. Re-run health, auth/session, message delivery, files, log-minimization, and schema checks before reopening traffic.
