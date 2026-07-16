# IceQ Security Status

Last reviewed: 2026-07-16. “Complete” means the scoped repository implementation and local automated evidence exist; it does not mean independently audited or production-accepted. See [threat model](threat-model.md), [operator runbook](operator-runbook.md), and [route audit](security-route-audit.md).

| Phase | Status | Repository evidence | Outstanding / owner |
|---|---|---|---|
| 0. Preliminary analysis | Complete for repository review; independent review outstanding | Architecture and trust boundaries are mapped in `README.md` and `docs/threat-model.md`; route evidence is in `docs/security-route-audit.md`. | Independent cryptographic audit and production penetration test are release blockers, not claims of this work. |
| 1. Tor integration | Blocked by explicit user sequencing; opt-in scaffolding only | `tor` and `caddy-tor` are excluded by default and enabled only by the Compose `tor` profile. `deploy/scripts/check-clearnet-compose.sh` checks that structural contract; `onion-address.sh` reads a locally generated hostname. | Do not boot Tor, advertise `Onion-Location`, or claim onion reachability until clearnet real-user acceptance. Later gates: key backup/restore, consensus publication, external onion reachability, and DNS-leak testing. Operator. |
| 2. E2EE | Complete for scoped implementation; audit outstanding | DM Signal/X3DH-ratchet code and signed-prekey/identity-change tests; safety text/QR comparison; client AES-GCM attachments with limits; group Sender Keys, epoch rotation, membership-bound distribution, replay checks, and encrypted group attachments. Primary paths: `web/src/lib/{signal,identityTrust,fileCrypto,senderKeys,groupCrypto}.ts`; matching `web/tests/*` plus backend group epoch/snapshot tests. | Independent crypto audit remains mandatory. E2EE cannot protect a compromised browser/served bundle or erase recipient copies. |
| 3. Backend hardening | Complete for scoped repository controls; operator storage work remains | Argon2id and bcrypt upgrade; refresh rotation/reuse handling; CSRF; durable wipe marker/session checks; authorization and per-action rate limits; durable ingest/outbox; Caddy headers/log filtering; container restrictions. Evidence is in backend tests, `docs/security-route-audit.md`, and migrations `001`-`013`. | At-rest volume/snapshot encryption, credential custody, monitoring, migration execution, and restore tests are operator responsibilities. Some route-audit rows remain source-review evidence rather than deployed penetration tests. Legacy pre-index ciphertext requires retention/offline handling. |
| 4. Anonymity/privacy | Partial | No email/phone requirement, no third-party analytics, minimized Caddy fields, sensitive route `log_skip`, privacy controls, disappearing-message server expiry, panic wipe, and no-JS help/install/security pages. | No complete metadata anonymity, padding, cover traffic, mix routing, or messaging without JavaScript. Backend/infrastructure log minimization needs live operator checks. Tor runtime is deferred. |
| 5. Frontend | Complete for scoped product phase | EN/TR typed catalogs, accessibility/source policies, safety QR, identity warnings, privacy/disappearing controls, PWA cache restrictions, WS plus polling fallback, group Sender Keys, and encrypted DM/group files are covered by `web/tests`. | Production browser/device acceptance remains outstanding; no-JS pages intentionally do not provide E2EE messaging. Push notifications are not implemented. |
| 6. Delivery/release | Partial | The committed Security CI definition covers Go test/vet/govulncheck, web test/typecheck/build/audit, Compose config, and secret scanning. `docs/operator-runbook.md` covers release, backups, incidents, and rollback. Local results are recorded separately below and do not imply that CI or runtime gates ran. | Production deploy and real-user clearnet acceptance are explicitly outstanding. Docker-backed smoke is a separate runtime gate. Tor follows only after acceptance. |

## Local verification evidence — 2026-07-16

| Gate | Exact result |
|---|---|
| `(cd backend && go test ./...)` | Exit 0. All discovered Go packages passed or reported no test files. |
| `(cd backend && go vet ./...)` | Exit 0. |
| `govulncheck ./...` | Not run: `govulncheck` was unavailable on `PATH`, and no local installation was authorized. The CI workflow installs pinned `v1.1.4`; that is workflow coverage, not local evidence. |
| `(cd web && npm test)` | Exit 0: 142 tests passed, 0 failed/skipped/cancelled. |
| `(cd web && npm run typecheck)` | Exit 0. |
| `(cd web && npm run build)` | Exit 0. Vite still reported curveasm/CommonJS/browser-externalization, ineffective dynamic-import, and over-500 kB chunk warnings. |
| `(cd web && npm audit --audit-level=high)` | Exit 0 at the High threshold, but reported one Moderate vulnerability: `protobufjs <=7.6.2`, `GHSA-f38q-mgvj-vph7`; npm reports a fix is available via `npm audit fix`. This is not a clean zero-finding audit. |
| `./deploy/scripts/check-compose-config.sh` | Exit 0. The checker used a temporary non-secret env for interpolation and left the pre-existing `deploy/.env.local` unchanged. Configuration validation only; no containers started. |
| `./deploy/scripts/check-clearnet-compose.sh` | Exit 0: `STATIC PASS` for the default clearnet-only/Tor-isolation/Caddy-policy source structure; runtime `SKIP` because `iceq/caddy:dev` was unavailable. This is not runtime Caddy proof. |
| Docker runtime and Caddy/Docker-backed smokes | Not run. Docker CLI was present, but `docker info` could not connect to the Docker daemon socket; the daemon was unavailable. |

## Required local gates

```bash
(cd backend && go test ./...)
(cd backend && go vet ./...)
(cd backend && govulncheck ./...)
(cd web && npm test)
(cd web && npm run typecheck)
(cd web && npm run build)
(cd web && npm audit --audit-level=high)
./deploy/scripts/check-compose-config.sh
```

`docker compose ... config --quiet` validates interpolation/model structure only; it does not start services, parse the custom Caddy image, apply migrations, or prove runtime behavior. If Docker is available, run the clearnet-only structural/runtime checker and relevant smoke tests separately. Do not enable the Tor profile in this phase.

## Existing-volume prerequisite

Docker init mounts run only for fresh volumes. Before starting updated services, compare the deployment's recorded migration ledger/schema state with `deploy/init/migrations/`, back up, apply each missing migration in numeric order, and verify the resulting tables/columns. Do not infer completion merely by retrying every file. Statements explicitly guarded by `IF NOT EXISTS`, including migration 013, are retry-safe additions; this is not a blanket idempotency claim for every historical migration, and a guard does not prove the existing object has the expected shape. Exact credential-safe commands and service ordering are maintained in `README.md`; execution, encrypted storage, restore rehearsal, and rollback approval belong to the operator.

## Release blockers

1. Resolve any Critical/High gate finding or document a reviewed, time-bounded exception.
2. Complete an independent cryptographic/security audit.
3. Perform backup/restore and migration rehearsal, then the explicitly approved production clearnet deploy.
4. Complete clearnet real-user acceptance before any Tor enablement or onion runtime/reachability claim.
