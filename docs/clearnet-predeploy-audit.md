# Clearnet Pre-deployment Security Audit

Audit date: 2026-07-27 (updated)
Previous audit date: 2026-07-16 (Phase 1-2 through `2d072d1`).
Scope: Release-candidate preparation through Phase 9; local source, unit tests,
build, dependency audit, migrations, Compose rendering, Caddy validation,
and .dockerignore verification. No VPS access, deployment, public smoke
mutation, or Tor implementation was performed.

## Result

The audited Phase 1-2 implementation claims are supported by the current source
and focused tests. No newly reproducible implementation defect was found, so no
production-code change or new regression test was warranted. Two documentation
claims had drifted: `security-status.md` still described the completed route and
service-rate-limit audit as remaining work, and `security-route-audit.md`
described ACK-coupled attachment cleanup as absent after it had been added. Both
documents now state the narrower evidence and remaining limits.

This is a local pre-deployment gate, not evidence that migrations are applied or
that the public deployment behaves identically.

## Claim-to-evidence inventory

| Claim | Implementation evidence | Executable evidence | Audit result / limit |
|---|---|---|---|
| Panic wipe and bounded ciphertext cleanup | `auth-service/handlers/panicwipe.go`, `scyllastore.go`; message writes maintain deletion indexes | `panicwipe_handler_test.go`, `panicwipe_cleanup_test.go`, `scyllastore_contract_test.go`, `message-service/store/deletion_index_contract_test.go` | Supported. Pre-004 ciphertext has no deletion-index row and needs offline handling or retention expiry. |
| Durable wipe marker and session rejection | PostgreSQL `wiped_accounts`; shared JWT verifier; per-frame WS wipe check | `shared/jwt/wiped_account_test.go`, panic-wipe tests, WS client tests | Supported. Existing volumes must apply migration 005; checks fail closed if durable status cannot be read. |
| Atomic refresh rotation and reuse handling | refresh row is consumed inside one PostgreSQL transaction before replacement issuance | `auth-service/handlers/refresh_test.go` including concurrent-use coverage | Supported by handler doubles; no live PostgreSQL concurrency smoke in this audit. |
| CSRF on cookie/session-changing and unsafe REST requests | shared `RequireCSRF`, auth/contact route mounts, web API header injection | `shared/middleware/csrf_test.go`, `auth-service/main_routes_test.go`, `web/tests/csrf-header-source.test.mjs` | Supported. Some mounts are source-contract tests rather than HTTP integration tests. |
| Route authentication and object authorization / IDOR resistance | authenticated actor comes from JWT context; DM canonical membership, group role, contact edge, file owner/grantee predicates | `docs/security-route-audit.md` plus auth, contacts, key, message, group, presence, and file authorization tests | Supported at the evidence level shown per route. Rows explicitly identify source-review-only gaps. |
| Redis service rate limits and private keys | authenticated UIN/action keys; anonymous rotating-HMAC edge identities; fail-closed Redis behavior | shared middleware tests, auth refresh tests, key bundle limiter tests | Supported. Caddy still sees remote identity transiently for edge defense; dedicated behavior tests do not exist for every route mount. |
| Presence privacy | self-or-accepted-contact predicate before Redis presence reads; unauthorized bulk entries omitted | `presence-service/main_authorization_test.go` | Supported. Presence/read/timing metadata remains inherent for authorized participants. |
| File owner/grantee authorization | migrations 006-007; upload ownership registration; download owner-or-grantee predicate; owner-constrained grant/revoke | `file-service/handlers/authorization_test.go` | Supported. Legacy objects fail closed without trusted backfill; group attachments remain disabled. |
| Attachment grant ACK cleanup | web in-memory lifecycle waits for positive ack and revokes on caller-reported failure, timeout, close/logout, or send failure with bounded retry | `web/tests/attachment-grant-lifecycle.test.ts`, `attachment-ui-source.test.mjs`, `ws-ack-source.test.mjs` | Supported for the live browser session. A crash before cleanup is not durably reconciled server-side. |
| Signal bundle/prekey bootstrap | authenticated startup repairs missing own bundle and monotonically tops up low unused OPKs | `web/tests/signal-bootstrap.test.ts`, `keys-api.test.ts` | Supported. This is provisioning behavior, not an external cryptographic review. |
| WebSocket authentication, routing, ack identity, and rate limits | auth-first client, authenticated sender overwrite, canonical DM/group checks, direct ack routing | `ws-gateway/client/auth_test.go`, `ws-gateway/router/router_test.go`, shared authenticated limiter tests | Supported by unit tests; public WSS behavior was not exercised. |
| Migrations 004-007 | Scylla deletion-index tables; PostgreSQL wiped-account, file-owner, and grant tables; Compose init mounts | migration files and `deploy/docker-compose.yml` render | Definitions and mounts supported. Initdb mounts only affect fresh volumes; application and verification on production remain a separate gate. |
| Caddy headers and minimized logs | HSTS, CSP, frame/content/referrer/permissions headers; sensitive header/IP deletion; `/ws` and message-history log skip | `deploy/Caddyfile` source review and Compose config validation | Supported as configuration. No local Caddy request/response integration test or public edge observation was run. |

## Commit inventory

Every commit from the Phase 1 baseline through the Phase 2 head is mapped below;
test- and documentation-only commits are included because they establish or
correct the executable-evidence contract.

| Commit | Claim / evidence contribution |
|---|---|
| `0665447` | Hardened sessions, CSRF, prekey bootstrap, panic-wipe baseline, and authenticated WS routing. |
| `952ad45` | Wired auth-service panic wipe to bounded Scylla ciphertext cleanup. |
| `7e4b67e` | Added exact Scylla deletion indexes, logged-batch maintenance, migration 004, and cleanup contract tests. |
| `1741700` | Added durable `wiped_accounts` revocation, JWT/WS checks, and migration 005. |
| `e19c735` | Documented the required existing-volume durable-revocation migration and fail-closed rollout contract. |
| `59a8a3d` | Documented executable Scylla deletion-index verification for migration 004. |
| `f314dc8` | Enforced authenticated ownership/actor scope, private anonymous limiter keys, file-owner registry, Caddy identity minimization, and the initial route audit. |
| `c1382b8` | Restricted presence reads to self or accepted contacts with uniform unauthorized behavior. |
| `45657a4` | Added owner-created encrypted-file grants, migration 007, recipient download authorization, and client grant wiring. |
| `f162d0b` | Added explicit Redis-backed authenticated per-action limits across protected service routes and WS frames. |
| `87cf46a` | Added authenticated rate limits to authorized presence reads. |
| `55fb0d9` | Added two-user authorization behavior evidence for key, message, file, and auth actor boundaries. |
| `dd20cd5` | Added contact and group row-level authorization behavior evidence. |
| `3d7ea61` | Tightened migrations 006-007, delivery rollback wiring, Caddy log filtering, and evidence wording. |
| `ab632c0` | Added a failing contract test requiring anonymous public-bundle limiting. |
| `60d29f1` | Closed remaining contact, group, and file object-authorization test cases and clarified migration rollout. |
| `3f36617` | Implemented rotating-HMAC Redis limiting before public bundle/OPK consumption. |
| `980161a` | Added verified-UIN Redis limiting to refresh rotation with behavioral tests. |
| `097871c` | Aligned refresh limiter behavior and route-audit claims with implementation evidence. |
| `1a99070` | Reconciled route matrix PASS wording with behavioral versus source-review-only evidence. |
| `9efb5f6` | Added the concurrent refresh-token reuse regression reproducer. |
| `4ce64cb` | Bound attachment grants to positive message acknowledgments and failure cleanup in the web client. |
| `5ee3065` | Atomically consumed refresh rows before replacement-token issuance, making concurrent reuse single-winner. |
| `2d072d1` | Added bounded grant-revocation retry, exhaustion recovery, idempotence, and ACK-race compensation. |

## Fresh local verification (historical — 2026-07-16)

> **Note:** The results below are from the Phase 1–2 audit scope (2026-07-16).
> Current results are in the "2026-07-27 release-candidate additions" section
> below and in `docs/security-status.md`. The test count has since grown from
> 47 to 322, and the dependency gate now reports 2 moderate react-router
> findings (accepted by policy) instead of the earlier protobufjs advisory.

- Focused Go packages: PASS (auth handlers/routes, shared CSRF/JWT/limiters,
  keys, message handlers/store, presence, files, WS client/router).
- Full backend: `cd backend && go test ./...` PASS.
- Web tests: `cd web && npm test` PASS, 47 tests (historical; 322 as of 2026-07-27).
- TypeScript: `cd web && npm run typecheck` PASS.
- Production bundle: `cd web && npm run build` PASS. Vite reports existing
  vendor `curveasm.js` compatibility warnings; the build exits zero and the
  regression suite verifies no broken `curveasm.wasm` placeholder/reference.
- Dependency gate: the earlier run reported one **moderate** `protobufjs`
  advisory. It was resolved in `f3968a9` by pinning exact direct
  `protobufjs@7.6.5`; fresh `npm audit --audit-level=moderate` and
  `npm audit --audit-level=moderate --omit=dev` runs both PASS with
  `0 vulnerabilities`. This preserves the historical finding without treating
  it as a current open issue.
- Compose: `docker compose -f deploy/docker-compose.yml config --quiet` PASS
  with the local example-derived environment. This validates rendering, not
  container startup or runtime health.

## 2026-07-27 release-candidate additions

- **React Router security gate**: `react-router-dom` downgraded from `^7.18.1` to exact `6.30.4`. Direct `react-router` dependency removed. This eliminates the HIGH-severity findings. The policy accepts only three reviewed advisory identifiers represented by two MODERATE package entries: the affected SSR/RSC path is unused, and the redirect path is constrained by the fixed-route AST regression gate. All 322 web tests, 48 E2E tests, typecheck, and build pass.
- **Caddy validation**: `check-clearnet-compose.sh` now invokes `caddy validate` (not bare `validate`). Both clearnet and Tor configs validated at runtime. Regression test added.
- **Root `.dockerignore`**: Excludes version control, hidden local state directories, environment files, `node_modules`, build artifacts, coverage, logs, and editor/OS metadata. `.env.example` explicitly re-included. Regression test verifies exclusions.
- **Redis authentication**: Production Redis requires `requirepass` + `ICEQ_REDIS_PASSWORD`. `ICEQ_REDIS_REQUIRE_AUTH=1` enforces non-empty password at startup. Acceptance uses synthetic `iceq-acceptance-redis`.
- **NATS authentication**: Production NATS enforces `--auth` token (`ICEQ_NATS_TOKEN`). All internal clients read token from environment. Acceptance uses synthetic `iceq-acceptance-nats`.
- **ScyllaDB mode**: Production defaults to `--developer-mode=0` via `ICEQ_SCYLLA_DEVELOPER_MODE`. Acceptance retains `--developer-mode=1`.
- **Migrations 014–017**: Panic Wipe PIN, challenge-signature key, wipe jobs table, and Scylla erasure indexes. All additive with guards.
- **Five-storage acceptance**: The disposable stack applied the real migration files, seeded PostgreSQL, Redis, ScyllaDB, NATS JetStream, and MinIO, then verified zero footprint for the wiped account and no change to a control account.

## Remaining pre-deployment concerns

1. Apply and verify all pending migrations (004-007, 010-017) on
   existing volumes before affected services start.
2. Obtain live clearnet HTTPS/WSS, authorization, rate-limit, panic-wipe, and
   file-grant smoke evidence only after the separate deployment approval gate.
3. `protobufjs@7.6.5` resolved; all web tests, typecheck, and build pass.
4. Add server-side expiry/reconciliation for attachment grants to cover browser
   crashes before the in-memory lifecycle can revoke them.
5. Complete backup and restore rehearsal against disposable data. Clean-schema migration application and the five-storage Panic Wipe acceptance path pass locally.
6. Complete independent cryptographic/security audit.
7. Retain the documented limitations: legacy pre-004 message cleanup, incomplete
   group E2EE, and lack of an external cryptographic/security review.
8. npm audit reports 2 moderate findings for react-router v6 (SSR/RSC features
   not used by IceQ's client-side SPA); no high or critical vulnerabilities.
