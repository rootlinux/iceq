# IceQ Security Status

Last reviewed: 2026-07-16

This report maps the requested IceQ security and anonymity checklist to the current codebase state. It is intentionally conservative: items are marked complete only when the repository contains implementation and local verification evidence.

## 0. Preliminary Analysis

Status: partial.

Implemented:
- Architecture is documented in `README.md`: React/Vite web client, Go microservices, PostgreSQL, ScyllaDB, Redis, NATS, MinIO, Caddy, and Tor.
- Existing E2EE, auth/session, file-service, Caddy, and message-storage paths were reviewed during the hardening passes.

Remaining:
- A full OWASP Top 10 audit with exploit proofs is not complete.
- E2EE still needs an external cryptographic review before production trust claims.

Tradeoff:
- The current work prioritized high-impact implementation gaps first, then this status report. A deeper audit should be a separate, repeatable security review.

## 1. Tor Network Integration

Status: deferred; repository assets retained as opt-in.

Implemented:
- Docker Compose retains a Tor v3 hidden-service container behind the explicit `tor` profile; the default clearnet stack excludes it.
- The `.onion` key material is generated automatically and persisted in the `tor_keys` volume.
- `deploy/scripts/onion-address.sh` prints the locally generated onion address and `ICEQ_ONION_LOCATION` value; this is not claimed as consensus-publication or reachability proof.
- Default Caddy loads only HTTPS sites. The explicit Tor profile adds an isolated `caddy-tor` HTTP edge that forwards to the default Caddy HTTPS route/header policy with system-trust certificate validation and `iceq.space` SNI; neither Tor service is instantiated by default. The Tor-edge healthcheck traverses this same upstream path to default Caddy's non-sensitive `/health` route.
- `Onion-Location` is enabled only when a non-empty `ICEQ_ONION_LOCATION` is configured; the default clearnet response does not advertise it.
- `deploy/scripts/check-clearnet-compose.sh` verifies default exclusion of both Tor services, explicit profile inclusion, edge isolation, clearnet hosts/routes, and required security headers. It labels structural-only evidence `STATIC PASS` and runtime parser absence `SKIP`.
- Caddy edge logging strips client IP, User-Agent, Authorization, and Cookie data and skips high-volume sensitive routes.

Remaining:
- Application-wide outbound traffic is not yet forced through a SOCKS5 Tor proxy.
- Live Tor boot and integration proof is intentionally deferred until after clearnet deployment and human acceptance.
- DNS-leak prevention for future outbound integrations must be enforced before adding such integrations.

Tradeoff:
- Tor is not part of the current deployment scope. Keeping its assets opt-in avoids accidental activation while preserving a reviewed starting point for the later Tor phase.

## 2. End-to-End Encryption

Status: partial.

Implemented:
- Client-side Signal Protocol flow is present for direct messages.
- Private keys are generated and stored client-side.
- Key-service stores public identity keys, signed prekeys, and one-time prekeys.
- The web client checks the server-side unused one-time-prekey count on authenticated startup and automatically uploads a monotonic top-up batch when the pool drops below the low-watermark.
- Safety-number helper exists for out-of-band identity comparison.
- Direct-message file attachments are encrypted client-side with AES-256-GCM before MinIO upload; the decrypt manifest is carried inside the Signal-encrypted message body.

Remaining:
- Group message E2EE still needs Sender Keys or MLS.
- Safety-number QR UX is not complete yet.
- The protocol implementation needs a focused crypto review, including signed-prekey verification and session lifecycle tests.

Tradeoff:
- Direct-message confidentiality is prioritized. Group E2EE is intentionally not hand-rolled until a clean Sender Keys or MLS design is selected.

## 3. Backend Hardening

Status: partial to mostly implemented.

Implemented:
- New password hashes use Argon2id.
- Legacy bcrypt hashes are upgraded after successful login.
- Refresh tokens use Secure, HttpOnly, SameSite=Strict cookies.
- Access tokens remain short-lived and compatible with current WebSocket bearer auth.
- Cookie/session-changing auth routes require the same-origin CSRF header `X-IceQ-CSRF: 1`; the web API client adds it automatically for refresh and unsafe REST methods.
- Caddy enforces HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, and X-Content-Type-Options.
- Optional Scylla TTL can expire encrypted message rows.
- Panic-wipe support removes keys, contacts, refresh tokens, group memberships, and message rows on destructive account wipe.
- Auth-service requires its Scylla session at startup and wires the same message store into automatic and manual panic-wipe paths. A minimal `wiped_accounts(uin, wiped_at)` marker commits in the PostgreSQL wipe transaction; JWT verification and every inbound WebSocket frame check it before Redis, so Redis is only a cache/fast path. The insert is idempotent and UINs come from a non-reused sequence, so later registrations cannot inherit or erase an old identity's marker. Session blocklisting completes before bounded best-effort ciphertext cleanup. Direct sender/receiver and group-sender index partitions provide exact primary keys, avoiding cluster-wide `ALLOW FILTERING` scans; new message rows and their deletion-index rows are committed in one logged batch.
- CI security workflow now runs backend tests, web tests/build, npm audit, and Compose config validation.

Remaining:
- The repository route surface has a route-by-route authentication, object-authorization, uniform-failure, and rate-limit audit in `docs/security-route-audit.md`. Rows distinguish behavioral tests from source-review-only evidence; this is repository evidence, not a production penetration-test claim.
- Database at-rest encryption is an operator/storage-layer task and is not fully automated here.
- Redis-backed, authenticated per-action rate limits cover auth/session mutation, contacts, key mutation/count, message/group reads and mutations, presence, file URLs/grants, and WebSocket connect/frame paths. Login, registration, and public bundle lookup use rotating-HMAC anonymous buckets behind the edge. Some route mounts remain source-review-only rather than dedicated behavior tests, as recorded in the route audit.
- Ciphertext written before migration `004_panic_wipe_message_indexes.cql` has no deletion-index row. Operators must handle that legacy data with a bounded offline migration or retention expiry; the online panic-wipe path intentionally never performs a cluster-wide scan.

Tradeoff:
- Cookie refresh improves token secrecy but requires CSRF discipline on state-changing cookie-auth endpoints.

## 4. Anonymity Requirements

Status: partial.

Implemented:
- Registration does not require email or phone.
- No analytics or third-party tracker integration is present.
- CSP is self-host oriented and removes third-party script/font allowances.
- Edge log minimization avoids persistent IP and User-Agent logging at Caddy.
- Panic-wipe infrastructure exists.

Remaining:
- Basic no-JS operation is not implemented for messaging.
- Timing padding/delayed send is not implemented.
- Metadata minimization still needs a deeper redesign around conversation IDs, routing metadata, presence, and read/typing signals.
- Disappearing messages need a user-facing control layered on top of the TTL storage primitive.

Tradeoff:
- Real-time usability still leaks some metadata. Reducing that further will require product tradeoffs around presence, typing, receipts, and delivery speed.

## 5. Frontend

Status: partial.

Implemented:
- Responsive dark UI exists.
- WebSocket real-time chat exists.
- Authenticated long-polling and HTTP send provide a bounded fallback when WebSocket transport is unavailable, and the client returns to WebSocket transport after recovery.
- Presence, typing, delivered receipts, and read receipts are independently controlled by privacy settings; presence subscriptions are opt-in on the gateway.
- Disappearing-message choices are enforced per message. Explicit `off` has no server-side expiry, while enabled durations are capped at 30 days.
- Direct-message encrypted attachment upload/download is wired.
- Panic-wipe settings UI exists.
- Automatic direct-message one-time-prekey replenishment runs during authenticated app bootstrap.
- Local decrypted chat state is kept in memory rather than persisted.

Remaining:
- Full Turkish/English i18n is not complete.
- QR-based safety verification is not complete.
- Group attachments are not complete.
- A hardened PWA/service-worker strategy is not complete.

Tradeoff:
- The app remains JavaScript-first because Signal Protocol and IndexedDB key storage require client-side crypto. A no-JS fallback can only support limited account/help flows, not true E2EE messaging.
- Authenticated `(sender_uin, client_id)` receipts and an opaque outbox are durable in Scylla. Disappearing messages apply one expiry to the receipt, message, indexes, and outbox; explicit `off` receipts have no arbitrary TTL. The gateway returns `persisted` only after message-service confirms the deterministic message row and outbox batch at quorum.
- Recipient fan-out uses a file-backed JetStream stream and deterministic `Nats-Msg-Id`. PubAck does not delete the Scylla outbox. A named durable gateway consumer atomically deduplicates and appends to the recipient Redis stream, reports that durable acceptance to message-service, then explicitly acknowledges JetStream. Only the acceptance receipt marks the Scylla receipt delivered and removes the outbox. Redelivery after a crash is a Redis no-op and does not create a second recipient queue item, including beyond JetStream's 24-hour producer duplicate window. Recipient/client message-ID checks remain defense in depth. Expiry removes server ciphertext and indexes but cannot erase copies already delivered to recipient devices or backups.
- `docs/durable-delivery-runbook.md` documents rollout gates, recovery, and the crash-window boundary.

## 6. Delivery

Status: partial.

Implemented:
- README documents the default clearnet command and separate explicit Tor-profile command.
- A baseline Git commit exists for future diffs.
- Focused unit/source tests cover Argon2id, cookies, CSRF middleware/header wiring, encrypted files, key API behavior, automatic prekey replenishment, safety fingerprinting, and attachment UI wiring.
- Security CI workflow is present.

Remaining:
- Live deployment validation should be repeated against the actual VPS/Docker environment.
- A production threat model and operator runbook should be added before public launch.
- External security review is still recommended before handling real sensitive traffic.

## Verification Commands

Run locally before shipping:

```bash
cd backend && go test ./...
cd web && npm ci && npm audit --audit-level=high && node --import tsx --test tests/*.test.mjs tests/*.test.ts && npm run build
cp deploy/.env.example deploy/.env.local
docker compose -f deploy/docker-compose.yml config --quiet
```

## Existing-volume rollout prerequisite

Docker initdb mounts execute only for fresh volumes. Existing deployments must apply and verify Scylla migrations `004_panic_wipe_message_indexes.cql`, `011_disappearing_messages.cql`, and `012_durable_message_ingest.cql` before starting the updated message-service. Migration 012 creates the durable authenticated receipt and outbox required before any `persisted` ACK can be returned. Separately, apply and verify PostgreSQL migration `005_wiped_accounts.sql` before starting the updated auth-service or ws-gateway. The README section “Existing database volumes: required security migrations” provides exact idempotent apply commands plus PostgreSQL and Scylla checks. Until required durable revocation or ingest tables exist, the affected authenticated path deliberately fails closed.

## Highest Priority Next Work

1. Finish safety-number UI with QR comparison.
2. Add a read-only message-retention indicator that exposes the active per-conversation expiry choice without revealing message content.
3. Design group E2EE with Sender Keys or MLS before implementing group attachments.
4. Exercise WebSocket-to-long-poll recovery against the deployed edge under realistic network interruption.
5. Add dedicated route-level behavior tests for the source-review-only rows identified in `docs/security-route-audit.md` and repeat the audit against the deployed edge.
