# Clearnet Pre-deployment Security Audit

Audit date: 2026-07-16  
Scope: Phase 1-2 repository claims through `2d072d1`; local source, unit tests,
build, dependency audit, migrations, and Compose rendering only. No VPS access,
deployment, public smoke mutation, or Tor implementation was performed.

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

The audited security chain is `0665447` (session/CSRF/prekey/WS baseline),
`952ad45`, `7e4b67e`, `1741700` (panic wipe, indexes, durable marker), `f314dc8`,
`c1382b8`, `45657a4`, `87cf46a`, `3d7ea61`, `60d29f1`, `3f36617`, `980161a`
(authorization, presence, file grants, and rate limits), `5ee3065` (atomic
refresh), and `4ce64cb` plus `2d072d1` (ack-bound cleanup and retry recovery).
Intermediate test/document-only commits were reviewed through the resulting
tree rather than treated as independent security claims.

## Fresh local verification

- Focused Go packages: PASS (auth handlers/routes, shared CSRF/JWT/limiters,
  keys, message handlers/store, presence, files, WS client/router).
- Full backend: `cd backend && go test ./...` PASS.
- Web tests: `cd web && npm test` PASS, 47 tests.
- TypeScript: `cd web && npm run typecheck` PASS.
- Production bundle: `cd web && npm run build` PASS. Vite reports existing
  vendor `curveasm.js` compatibility warnings; the build exits zero and the
  regression suite verifies no broken `curveasm.wasm` placeholder/reference.
- Dependency gate: `cd web && npm audit --audit-level=high` PASS at the requested
  threshold; npm reports one **moderate** `protobufjs` advisory, so the tree is
  not vulnerability-free.
- Compose: `docker compose -f deploy/docker-compose.yml config --quiet` PASS
  with the local example-derived environment. This validates rendering, not
  container startup or runtime health.

## Remaining pre-deployment concerns

1. Apply and verify Scylla migration 004 and PostgreSQL migrations 005-007 on
   existing volumes before affected services start.
2. Obtain live clearnet HTTPS/WSS, authorization, rate-limit, panic-wipe, and
   file-grant smoke evidence only after the separate deployment approval gate.
3. Resolve or explicitly accept the moderate `protobufjs` advisory after
   compatibility review; it does not fail the configured high-severity gate.
4. Add server-side expiry/reconciliation for attachment grants to cover browser
   crashes before the in-memory lifecycle can revoke them.
5. Retain the documented limitations: legacy pre-004 message cleanup, incomplete
   group E2EE, and lack of an external cryptographic/security review.
