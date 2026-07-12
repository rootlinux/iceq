# IceQ

IceQ is a privacy-first, end-to-end encrypted messenger built on the Signal Protocol. The server is a blind relay — it stores and forwards opaque ciphertext but can never read message content, even under compulsion or breach.

## Architecture

```
Browser / Tor client
      │  HTTPS / WSS (direct)        │  .onion (Tor)
      ▼                              ▼
┌─────────────────────────────────────────────────────┐
│  Caddy (TLS termination, rate limiting, CSP headers) │◄── iceq-tor (v3
└──────────────────────┬──────────────────────────────┘     hidden service)
                       │  Docker bridge (iceq-net)
     ┌─────────────────┼──────────────────────┐
     │                 │                      │
     ▼                 ▼                      ▼
auth-service      ws-gateway           key-service
(users, tokens,   (WebSocket hub,      (Signal prekey
 contacts,         fan-out via NATS)    bundle store)
 groups)
     │                 │
     │    NATS bus     │
     └─────────┬───────┘
               │
     ┌─────────┼──────────────┐
     │         │              │
     ▼         ▼              ▼
message-    presence-      file-service
service     service        (pre-signed
(ScyllaDB   (Redis         MinIO URLs,
 ciphertext) presence map)  never sees
                            file bytes)

Infrastructure: PostgreSQL · ScyllaDB · Redis · NATS · MinIO · Tor
```

## Quick Start

```bash
# 1. Clone
git clone <repo-url> && cd iceq

# 2. Copy env template and fill in secrets
cp deploy/.env.example deploy/.env.local
$EDITOR deploy/.env.local   # set passwords, JWT secret, allowed origins

# 3. Build and start
docker compose -f deploy/docker-compose.yml up --build

# 4. Open the app
open https://localhost        # accept the self-signed dev cert
```

## Services

| Service          | Internal port | Purpose                                    |
|------------------|---------------|--------------------------------------------|
| caddy            | 443 (public)  | TLS termination, rate limiting, SPA serving|
| tor              | —             | v3 hidden service gateway to Caddy (:80)   |
| auth-service     | 8080          | Registration, login, JWT, contacts, groups |
| key-service      | 8081          | Signal Protocol prekey bundle distribution |
| ws-gateway       | 8082          | WebSocket hub, NATS fan-out                |
| message-service  | 8080          | ScyllaDB ciphertext persistence + history  |
| presence-service | 8080          | Online/away/offline presence map           |
| file-service     | 8080          | Pre-signed MinIO URL minting               |
| postgres         | 5432 (internal)| Users, contacts, groups, refresh tokens   |
| scylla           | 9042 (internal)| Message ciphertext store                  |
| redis            | 6379 (internal)| Presence map, JWT blocklist, rate counters |
| nats             | 4222 (internal)| Inter-service message bus (JetStream)      |
| minio            | 9000 (internal)| S3-compatible file object store            |

## E2EE Design

IceQ implements the Signal Protocol (X3DH key agreement + Double Ratchet message encryption) entirely on the client. Every message is encrypted before it leaves the device using the recipient's prekey bundle fetched from key-service. The server receives, stores, and forwards opaque byte blobs — it holds no decryption keys and cannot read message content. Keys never leave the originating device.

Direct-message safety numbers are computed client-side from the two users' UINs and identity public keys. The helper returns a stable 12-group decimal fingerprint that users can compare out of band; a mismatch means the peer identity key changed and the conversation should not be trusted until verified.

## Privacy Guarantees

- Messages are encrypted before transmission; the server stores only ciphertext
- Direct-message file attachments are encrypted client-side with AES-256-GCM before MinIO upload; the object key and decrypt manifest are carried inside the Signal-encrypted message body, not as a raw presigned URL
- Edge access logs strip client IP, User-Agent, Authorization, and Cookie fields; remaining backend UIN/username log lines are tracked as a hardening limitation
- WebSocket and message-history routes are excluded from Caddy access logs with `log_skip`
- Pre-signed file URLs: the file-service mints a URL and never sees the bytes
- Bearer tokens are bound to a Redis blocklist; logout is cryptographically enforced
- Panic-wipe feature: a duress password triggers irreversible deletion of all user data
- Caddy does not forward the real client IP to backend services after edge hardening
- Optional Scylla TTL can expire encrypted message rows after a configured retention window
- `read_only` container filesystems prevent runtime tampering

## Security Features

- **Rate limiting at edge** — login 5/min, register 3/min, all API 60/min, WebSocket 10/min per IP
- **JWT rotation** — short-lived access tokens (15 min) + refresh rotation; revoked tokens blocklisted in Redis
- **Prekey replenishment contract** — frontend accepts key-service `204 No Content` responses when uploading one-time prekeys
- **HSTS + CSP** - strict self-hosted browser policy enforced by Caddy; no third-party fonts or scripts
- **Panic wipe** — duress password triggers async deletion of messages, keys, contacts, and account
- **Read-only containers** — all services run with `read_only: true`; only `/tmp` tmpfs is writable
- **No-new-privileges** — `no-new-privileges:true` on every container prevents privilege escalation
- **Resource limits** — each container is capped at CPU and memory to limit blast radius

## Tor Hidden Service

IceQ runs as a Tor v3 hidden service out of the box. The `.onion` address is auto-generated on first boot and stored in the `tor_keys` Docker volume. Onion-Location is optional and must be enabled after that address is known by setting `ICEQ_ONION_LOCATION` in `deploy/.env.local`.

### Get your .onion address

```bash
docker compose -f deploy/docker-compose.yml up -d
./deploy/scripts/onion-address.sh
```

The script polls the Tor container until the v3 keypair has been generated and published to the Tor directory consensus (typically 30–60s on first boot), then prints a URL like:

```
http://iceq...abc...xyz.onion
```

It also prints the exact `ICEQ_ONION_LOCATION=http://...onion` line to add to `deploy/.env.local`. Keep this value on the v3 onion URL; do not point Onion-Location at a clearnet domain.

Open that address in a Tor-capable browser (Tor Browser, Brave with private window + Tor, etc.) to use IceQ over the Tor network.

### Backup your .onion keypair (CRITICAL)

Your `.onion` address is derived from a private key stored in the `tor_keys` Docker volume. **If this volume is deleted, your address is lost forever and cannot be recovered** — Tor has no recovery mechanism for v3 keys.

**Backup:**

```bash
mkdir -p backup
docker run --rm \
  -v iceq_tor_keys:/source:ro \
  -v $(pwd)/backup:/backup \
  alpine tar czf /backup/tor_keys_backup.tar.gz -C /source .
```

Store `backup/tor_keys_backup.tar.gz` offline (USB drive, encrypted disk, paper backup of the hash for integrity). Do not commit it to git.

**Restore:**

```bash
docker run --rm \
  -v iceq_tor_keys:/target \
  -v $(pwd)/backup:/backup \
  alpine tar xzf /backup/tor_keys_backup.tar.gz -C /target
```

After a restore, restart the Tor container to pick up the keypair:

```bash
docker compose -f deploy/docker-compose.yml restart tor
./deploy/scripts/onion-address.sh   # should print the same address
```

### How it works

```
Tor Browser ──► Tor Network ──► iceq-tor container ──► Caddy (:80 inside iceq-net)
                                                  │
                                                  └─► import (iceq_routes) — same
                                                      routing as direct HTTPS
```

> **Why plain HTTP between Tor and Caddy is acceptable for this deployment:** Tor provides transport encryption between the client and the Tor container. The Tor-to-Caddy hop stays inside Docker's internal `iceq-net` bridge and is not host-exposed. TLS on this hop would add CPU cost and certificate-management complexity; operators with stricter container-network isolation requirements can split Tor and Caddy onto a dedicated bridge in a later hardening pass.

The `goldy/tor-hidden-service` container:
- generates a v3 ed25519 keypair on first boot and persists it in `tor_keys`
- strips Tor's transport encryption and forwards plain HTTP into the Docker network
- exposes the v3 onion address via its `hostname` file (used by the script above)

Caddy serves both `:80` (Tor traffic) and `https://localhost` (direct browser access) from the same `(iceq_routes)` snippet, so `.onion` users and direct-HTTPS users get identical IceQ functionality.

### Security note

Tor provides **transport-layer anonymity** for clients reaching your instance. The Signal Protocol still provides **end-to-end message encryption** — the server cannot read message content regardless of transport, even if the Tor layer is compromised or the operator is compelled to log.

## Development

```bash
# Build all Go services
cd backend && go build ./...

# Run unit/integration tests
cd backend && go test ./...

# Build the frontend
cd web && npm ci && npm run build

# Smoke tests (requires running Docker stack)
cd backend && go run ./cmd_smoke_step10/
```

## Known Limitations

- **Group attachments** — direct-message attachments are encrypted and wired in the chat UI; group attachment E2EE still waits on the group encryption design
- **One-time prekey automation** — the key-service and frontend API support replenishment, but automatic low-watermark upload still needs a background client flow
- **Batch read receipts** — read receipts are per-message; a bulk-ACK endpoint is not yet implemented
- **Push notifications** — offline push (APNs/FCM) is not implemented; unread messages are delivered on next WebSocket reconnect
- **Legacy bcrypt accounts** - new passwords use Argon2id; existing bcrypt hashes upgrade automatically after a successful login
- **WebSocket bearer compatibility** - refresh tokens now use HttpOnly cookies, but WebSocket auth still needs the short-lived access token until ws-gateway supports cookie auth
- **Metadata-reduced message storage** - optional message TTL is available, but conversation IDs and sender/receiver routing metadata still need a deeper minimization redesign
