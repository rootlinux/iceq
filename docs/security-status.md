# IceQ Security Status

Last reviewed: 2026-07-12

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

Status: partial to mostly implemented.

Implemented:
- Docker Compose includes a Tor v3 hidden-service container.
- The `.onion` key material is generated automatically and persisted in the `tor_keys` volume.
- `deploy/scripts/onion-address.sh` prints the generated onion address and `ICEQ_ONION_LOCATION` value.
- Caddy can serve clearnet and onion traffic from the same route set.
- `Onion-Location` is enabled when `ICEQ_ONION_LOCATION` is configured.
- Caddy edge logging strips client IP, User-Agent, Authorization, and Cookie data and skips high-volume sensitive routes.

Remaining:
- Application-wide outbound traffic is not yet forced through a SOCKS5 Tor proxy.
- No live Docker/Tor boot proof is recorded in this checkout because the previous local environment did not provide a usable Docker daemon.
- DNS-leak prevention for future outbound integrations must be enforced before adding such integrations.

Tradeoff:
- Tor ingress is in place without making every internal service Tor-aware. That keeps the stack simpler but means future outbound network code needs a hard policy gate.

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
- CI security workflow now runs backend tests, web tests/build, npm audit, and Compose config validation.

Remaining:
- IDOR and tenant isolation need a route-by-route audit.
- Database at-rest encryption is an operator/storage-layer task and is not fully automated here.
- Rate limiting is primarily edge-level; service-level abuse controls should be expanded.

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
- Direct-message encrypted attachment upload/download is wired.
- Panic-wipe settings UI exists.
- Automatic direct-message one-time-prekey replenishment runs during authenticated app bootstrap.
- Local decrypted chat state is kept in memory rather than persisted.

Remaining:
- Long-polling fallback for Tor-hostile WebSocket paths is not complete.
- Full Turkish/English i18n is not complete.
- QR-based safety verification is not complete.
- Group attachments are not complete.
- A hardened PWA/service-worker strategy is not complete.

Tradeoff:
- The app remains JavaScript-first because Signal Protocol and IndexedDB key storage require client-side crypto. A no-JS fallback can only support limited account/help flows, not true E2EE messaging.

## 6. Delivery

Status: partial.

Implemented:
- README includes Docker and Tor setup.
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
cd web && npm ci && npm audit --audit-level=high && node --test tests/*.test.mjs tests/*.test.ts && npm run build
cp deploy/.env.example deploy/.env.local
docker compose -f deploy/docker-compose.yml config --quiet
```

## Highest Priority Next Work

1. Finish safety-number UI with QR comparison.
2. Add a read-only message-retention indicator before offering user-controlled disappearing-message settings.
3. Design group E2EE with Sender Keys or MLS before implementing group attachments.
4. Add long-polling fallback for WebSocket-hostile paths.
5. Complete route-by-route IDOR and tenant-isolation audit.
