# Security Policy

## Reporting a vulnerability

**Do not disclose security vulnerabilities in public Issues.**

Please use [GitHub Private Vulnerability Reporting](https://github.com/rootlinux/iceq/security/advisories/new) if available for this repository. If that is not available, contact the repository owner directly through a private channel.

Include:

- A clear description of the issue
- Steps to reproduce
- Affected components and versions
- Any suggested mitigations

## Scope

The following are in scope for security reports:

| Component | Notes |
|---|---|
| E2EE implementation (X3DH, Double Ratchet, Sender Keys) | `web/src/lib/signal.ts`, `web/src/lib/senderKeys.ts`, `web/src/lib/groupCrypto.ts` |
| Client-side attachment encryption | `web/src/lib/fileCrypto.ts` |
| Authentication, session, and token handling | `backend/auth-service/` |
| Panic Wipe | `backend/auth-service/handlers/panicwipe*.go` |
| Identity / safety-number verification | `web/src/lib/identityTrust.ts`, `web/src/components/Settings/SafetyQr.tsx` |
| WebSocket gateway authentication and authorization | `backend/ws-gateway/` |
| Caddy edge security headers and rate limiting | `deploy/Caddyfile` |
| Key management and prekey distribution | `backend/key-service/` |
| Security CI gates | `.github/workflows/security-ci.yml` |

## Out of scope

- Issues that require physical access to the operator's infrastructure
- Vulnerabilities in third-party services outside the IceQ deployment boundary
- Social engineering of operators or users
- Denial-of-service attacks (availability is not guaranteed — see the [threat model](docs/threat-model.md))
- Vulnerabilities in the user's browser, OS, or extensions

## Important disclosures

- **Independent cryptographic audit is pending.** The E2EE implementation, while based on established Signal Protocol primitives, has not been reviewed by an independent cryptographer. See [Security Status](docs/security-status.md).
- **Tor is deferred.** The opt-in Tor hidden-service profile is scaffolding only and has not completed runtime boot, consensus publication, or external reachability testing.
- **The browser is the E2EE trust boundary.** A compromised or malicious server can serve JavaScript that captures keys and plaintext. See the [threat model](docs/threat-model.md).

## Supported versions

Only the latest commit on the default branch receives security patches. There are no backport or LTS branches.
