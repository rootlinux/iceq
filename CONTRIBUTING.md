# Contributing to IceQ

## Security-first development

IceQ is a security-sensitive encrypted messaging project. Every change must preserve or improve security properties. When in doubt, ask before changing cryptographic or authentication code.

## Before you start

1. Read the [threat model](docs/threat-model.md) and [security status](docs/security-status.md).
2. Read the [operator runbook](docs/operator-runbook.md) to understand deployment and operational constraints.
3. Run the local gates in [security-status.md](docs/security-status.md#required-local-gates) to confirm a clean baseline.

## Crypto-sensitive changes

Changes touching any of these areas require careful review and tests:

| Area | Key files |
|---|---|
| X3DH key agreement | `web/src/lib/signal.ts` |
| Double Ratchet | `web/src/lib/signal.ts` |
| Sender Keys | `web/src/lib/senderKeys.ts`, `web/src/lib/groupCrypto.ts` |
| Identity keys and prekeys | `web/src/lib/signal.ts`, `web/src/lib/identityTrust.ts` |
| Key persistence | `web/src/lib/indexeddb.ts` |
| Safety-number verification | `web/src/lib/identityTrust.ts`, `web/src/components/Settings/SafetyQr.tsx` |
| Attachment encryption | `web/src/lib/fileCrypto.ts` |
| Authentication and sessions | `backend/auth-service/` |
| Panic Wipe | `backend/auth-service/handlers/panicwipe*.go` |
| WebSocket authentication | `backend/ws-gateway/` |
| Caddy / security headers | `deploy/Caddyfile`, `deploy/Caddyfile.tor` |
| Security CI | `.github/workflows/security-ci.yml` |

### Rules for crypto-sensitive changes

- **Do not invent new cryptographic primitives.** Use only established, well-reviewed constructions.
- **Do not replace established primitives with simplified implementations.** Signal Protocol operations should remain in `web/src/lib/signal.ts` using the audited dependency.
- **Add test vectors or regression tests** where practical. Existing crypto tests are in `web/tests/signal-*.test.ts`, `web/tests/sender-keys.test.ts`, `web/tests/file-crypto*.test.ts`.
- **Update documentation** when changing threat-model-relevant behavior. If a change alters what the server can observe, what metadata is visible, or what guarantees hold, reflect that in `docs/threat-model.md`.
- **Keep changes isolated and reviewable.** A PR that changes both a cryptographic primitive and a UI layout in the same diff is harder to review than two separate PRs.

## Development workflow

1. **Fork and branch.** Work on a feature branch off the default branch.
2. **Run local gates** before pushing:

   ```bash
   (cd backend && go test ./...)
   (cd backend && go vet ./...)
   (cd web && npm test)
   (cd web && npm run typecheck)
   (cd web && npm run build)
   (cd web && node --import tsx scripts/audit-policy.mts)
   ./deploy/scripts/check-compose-config.sh
   ```

3. **Write tests.** New features need tests. Bug fixes need regression tests.
4. **Open a PR.** The Security CI workflow must pass.

## Dependency changes

- npm dependency changes must pass the audit-policy gate (`web/scripts/audit-policy.mts`).
- Go dependency changes must pass `go vet` and `govulncheck`.
- Do not introduce `latest` or floating image tags in Dockerfiles or Compose files.

## Style

- Go: standard `gofmt` / `go vet`.
- TypeScript/React: project ESLint and Prettier config in `web/`.
- Commit messages: follow [conventional commits](https://www.conventionalcommits.org/).

## License

A license has not yet been chosen by the project owner. Until one is applied, assume all rights reserved. Do not redistribute code without the owner's explicit permission.
