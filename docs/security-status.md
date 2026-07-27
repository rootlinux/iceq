# IceQ Security Status

Last reviewed: 2026-07-27. “Complete” means the scoped repository implementation and local automated evidence exist; it does not mean independently audited or production-accepted. See [threat model](threat-model.md), [operator runbook](operator-runbook.md), and [route audit](security-route-audit.md).

| Phase | Status | Repository evidence | Outstanding / owner |
|---|---|---|---|
| 0. Preliminary analysis | Complete for repository review; independent review outstanding | Architecture and trust boundaries are mapped in `README.md` and `docs/threat-model.md`; route evidence is in `docs/security-route-audit.md`. | Independent cryptographic audit and production penetration test are release blockers, not claims of this work. |
| 1. Tor integration | Blocked by explicit user sequencing; opt-in scaffolding only | `tor` and `caddy-tor` are excluded by default and enabled only by the Compose `tor` profile. `deploy/scripts/check-clearnet-compose.sh` checks that structural contract; `onion-address.sh` reads a locally generated hostname. | Do not boot Tor, advertise `Onion-Location`, or claim onion reachability until clearnet real-user acceptance. Later gates: key backup/restore, consensus publication, external onion reachability, and DNS-leak testing. Operator. |
| 2. E2EE | Complete for scoped implementation; audit outstanding | DM Signal/X3DH-ratchet code and signed-prekey/identity-change tests; safety text/QR comparison; client AES-GCM attachments with limits; group Sender Keys, epoch rotation, membership-bound distribution, replay checks, and encrypted group attachments. Primary paths: `web/src/lib/{signal,identityTrust,fileCrypto,senderKeys,groupCrypto}.ts`; matching `web/tests/*` plus backend group epoch/snapshot tests. | Independent crypto audit remains mandatory. E2EE cannot protect a compromised browser/served bundle or erase recipient copies. |
| 3. Backend hardening | Complete for scoped repository controls; operator storage work remains | Argon2id and bcrypt upgrade; atomic refresh-reuse epoch/row revocation; CSRF; durable wipe marker/session checks; authorization and per-action rate limits; durable ingest/outbox; Caddy headers/log filtering; container restrictions. Evidence is in backend tests, `docs/security-route-audit.md`, and migrations `001`-`017`. | At-rest volume/snapshot encryption, credential custody, monitoring, migration execution, and restore tests are operator responsibilities. Some route-audit rows remain source-review evidence rather than deployed penetration tests. Legacy pre-index ciphertext requires retention/offline handling. |
| 4. Anonymity/privacy | Partial | No email/phone requirement, no third-party analytics, minimized Caddy fields, sensitive route `log_skip`, privacy controls, disappearing-message server expiry, panic wipe, no-JS help/install/security pages, and an internal no-log edge signer so application upstreams receive a versioned rotating HMAC instead of raw client IP. | No complete metadata anonymity, padding, cover traffic, mix routing, or messaging without JavaScript. Backend/infrastructure log minimization and edge signer behavior still need live operator checks. Tor runtime is deferred. |
| 5. Frontend | Complete for scoped product phase | EN/TR typed catalogs, accessibility/source policies, safety QR, identity warnings, privacy/disappearing controls, PWA cache restrictions, WS plus polling fallback, group Sender Keys, and encrypted DM/group files are covered by `web/tests`. | Production browser/device acceptance remains outstanding; no-JS pages intentionally do not provide E2EE messaging. Push notifications are not implemented. |
| 6. Delivery/release | Partial | The committed Security CI definition covers Go test/vet/govulncheck, web test/typecheck/build/audit, Compose config, and secret scanning. `docs/operator-runbook.md` covers release, backups, incidents, and rollback. Local results are recorded separately below and do not imply that CI or runtime gates ran. | Production deploy and real-user clearnet acceptance are explicitly outstanding. Docker-backed smoke is a separate runtime gate. Tor follows only after acceptance. |

## Local verification evidence — 2026-07-27

| Gate | Exact result |
|---|---|
| `(cd backend && go test ./...)` | Exit 0. |
| `(cd backend && go vet ./...)` | Exit 0. |
| `(cd backend && go test -race ./...)` | Race detector enabled; no races reported. |
| `govulncheck ./...` | Not run locally (binary unavailable). CI workflow installs pinned `v1.1.4` and runs this gate on every push/PR; CI execution is a configured future command, not completed local evidence. |
| `(cd web && npm test)` | Exit 0: 322 tests passed, 0 failed/skipped/cancelled. |
| `(cd web && npm run typecheck)` | Exit 0. |
| `(cd web && npm run build)` | Exit 0. Pre-existing vendor `curveasm.js` compatibility warnings remain; build exit is zero. |
| `(cd web && npm audit --audit-level=moderate)` | Exit 1 (2 moderate react-router component entries covering 3 advisory identifiers). See React Router security gate below for applicability analysis. No high or critical vulnerabilities. `react-router-dom@6.30.4` (exact), `react-router@6.30.4` (transitive). |
| `(cd web && npm audit --audit-level=moderate --omit=dev)` | Same result as above. |
| Playwright E2E | 48/48 passed across Chromium desktop, Chromium Android, WebKit desktop, and WebKit iOS. |
| `./deploy/scripts/check-compose-config.sh` | Exit 0. |
| `./deploy/scripts/check-edge-identity.test.sh` | Exit 0. |
| `./deploy/scripts/check-clearnet-compose.sh` | Exit 0. Both clearnet and Tor Caddyfile configurations validated at runtime via `caddy validate`. |
| `./deploy/scripts/check-clearnet-compose-command.test.sh` | Exit 0. Regression test enforces `caddy validate` invocation (not bare `validate`). |
| `./deploy/scripts/check-dockerignore.test.sh` | Exit 0. `.dockerignore` excludes secrets, local tool directories, node_modules, and build artifacts; preserves all required build inputs. |
| Caddy image rebuild | PASS. `iceq/caddy:dev` rebuilt successfully with `.dockerignore` exclusions. |
| Five-storage Panic Wipe acceptance | Exit 0. Disposable PostgreSQL, Redis, ScyllaDB, NATS JetStream, and MinIO were seeded; the wiped account reached zero footprint and the control account remained unchanged. |
| Disposable migration rehearsal | Exit 0 for clean-schema application of the real PostgreSQL migration set through 016 and the required Scylla schema/migrations through 017 used by the acceptance harness. Backup/restore rehearsal remains pending. |

### React Router security gate

npm audit reports two moderate vulnerable package entries containing three reviewed advisories.

`react-router-dom` is pinned at exact `6.30.4`. IceQ imports exclusively from `react-router-dom`; there is no direct `react-router` dependency. The application uses client-only `BrowserRouter` declarative mode — no SSR, no RSC, no Framework Mode, no Data Mode, no server hydration, no loaders, and no actions.

| GHSA | Package | Applicability |
|---|---|---|
| GHSA-337j-9hxr-rhxg | react-router (transitive) | **Not applicable.** Affects Framework/Data Mode applications performing manual SSR hydration via `deserializeErrors()`. IceQ uses client-only `BrowserRouter` declarative mode and does not use the affected SSR path. |
| GHSA-wrjc-x8rr-h8h6 | react-router (transitive) | **Temporarily accepted.** Open redirect via backslash in `<Link>` and `useNavigate`. Requires an attacker-controlled destination to reach the navigation primitive. Current IceQ production navigation destinations are fixed internal routes (`/login`, `/app`, `/setup`, `/recovery`, `/register`). No user-controlled redirect destination was found. |
| GHSA-jjmj-jmhj-qwj2 | react-router-dom (direct) | **Temporarily accepted.** Open redirect leading to XSS in `<Link>` and `useNavigate`. Same applicability rationale as GHSA-wrjc-x8rr-h8h6 — fixed internal routes only. |

These three advisories are temporarily accepted **only while `react-router` and `react-router-dom` remain exactly `6.30.4`** and are guarded by:
- A CI `audit-policy` script (`web/scripts/audit-policy.mts`) that parses `npm audit --json`, allows only the three exact GHSA identifiers above, fails on any new or unknown advisory, fails on any high or critical vulnerability, and fails if the version pin changes;
- A TypeScript AST-based regression test (`web/tests/router-regression.test.ts`) that fails if attacker-controlled destinations, SSR/RSC/Data Mode APIs, or migration patterns are introduced.

**Review/expiry:** 2026-10-27. These findings remain scheduled for later Router migration.

### Internal infrastructure hardening

- **Redis**: Production Redis requires `ICEQ_REDIS_PASSWORD` via `requirepass`; `ICEQ_REDIS_REQUIRE_AUTH=1` enforces non-empty password at service startup. Healthchecks include auth. Acceptance uses synthetic `iceq-acceptance-redis`.
- **NATS**: Production NATS enforces `--auth` token (`ICEQ_NATS_TOKEN`). All internal clients read the token from environment. Acceptance uses synthetic `iceq-acceptance-nats`.
- **ScyllaDB**: Production Compose defaults to `--developer-mode=0` via `ICEQ_SCYLLA_DEVELOPER_MODE`. Acceptance Compose retains `--developer-mode=1` (explicitly disposable).

### New migrations

Migrations 014–017 are additive and guarded with `IF NOT EXISTS`:
- `014_panic_wipe_pin.sql` — Optional PIN-gated panic-wipe trigger.
- `015_wipe_public_key.sql` — Dedicated challenge-signature verification key (replaces PIN).
- `016_wipe_jobs.sql` — Durable asynchronous wipe-job table with lease-based crash recovery.
- `017_user_erasure_indexes.cql` — Scylla erasure indexes for complete user footprint deletion.

## Required local gates

```bash
(cd backend && go test ./...)
(cd backend && go vet ./...)
# govulncheck is CI-only (pinned v1.1.4 in security-ci.yml); not a local gate
(cd web && npm test)
(cd web && npm run typecheck)
(cd web && npm run build)
(cd web && node --import tsx scripts/audit-policy.mts)
(cd web && node --import tsx scripts/audit-policy.mts --production)
./deploy/scripts/check-compose-config.sh
```

`docker compose ... config --quiet` validates interpolation/model structure only; it does not start services, parse the custom Caddy image, apply migrations, or prove runtime behavior. If Docker is available, run the clearnet-only structural/runtime checker and relevant smoke tests separately. Do not enable the Tor profile in this phase.

## Existing-volume prerequisite

Docker init mounts run only for fresh volumes. Before starting updated services, compare the deployment's recorded migration ledger/schema state with `deploy/init/migrations/`, back up, apply each missing migration in numeric order, and verify the resulting tables/columns. Do not infer completion merely by retrying every file. Statements explicitly guarded by `IF NOT EXISTS`, including migration 013, are retry-safe additions; this is not a blanket idempotency claim for every historical migration, and a guard does not prove the existing object has the expected shape. Exact credential-safe commands and service ordering are maintained in `README.md`; execution, encrypted storage, restore rehearsal, and rollback approval belong to the operator.

## Release blockers

1. Resolve any Critical/High gate finding or document a reviewed, time-bounded exception.
2. Complete an independent cryptographic/security audit.
3. Perform the backup/restore rehearsal, compare the target schema with migrations 001–017, and apply only missing migrations before the explicitly approved production clearnet deploy.
4. Complete clearnet real-user acceptance before any Tor enablement or onion runtime/reachability claim.
