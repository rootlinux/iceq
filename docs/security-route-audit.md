# Security Route Audit

Audit date: 2026-07-16. Scope: every repository route mounted below `/api` or
`/ws`. `actor` always means `middleware.GetUIN` populated by `BearerAuth`; a
body, path, or query UIN is never accepted as the actor.

## Route matrix

| Route | Authentication source | Object / authorization predicate | Allowed role | Rate-limit key | Uniform public failure | Evidence |
|---|---|---|---|---|---|---|
| `POST /api/auth/register` | open; edge identity header | new user; unique conflicts intentionally collapse | anonymous | rotating HMAC(edge identity, `register`), 3/min | generic `USER_EXISTS`; limiter fails closed | handler test suite PASS |
| `POST /api/auth/login` | open; edge identity header | `qFindUserByIdentifier`; identifier existence hidden by decoy hash | anonymous | rotating HMAC(edge identity, `login`), 5/min | `INVALID_CREDENTIALS`; limiter fails closed | handler test suite PASS |
| `POST /api/auth/refresh` | HttpOnly refresh cookie + CSRF | refresh row/token owner and current session epoch | token owner | edge limit; service authenticated key contract is `auth:<uin>:auth:refresh` | generic token errors | auth tests PASS |
| `POST /api/auth/logout` | access/refresh token + CSRF | current session token rows | token owner | `auth:<uin>:auth:logout` contract | generic token errors; idempotent | auth tests PASS |
| `GET /api/auth/settings` | Bearer JWT | `qGetSettings WHERE uin=$1` | self | `auth:<uin>:auth:settings-read` contract | generic auth/not-found | auth tests PASS |
| `PUT /api/auth/settings` | Bearer JWT + CSRF | `qUpsertSettings`, actor UIN | self | `auth:<uin>:auth:settings-write` contract | generic validation/auth | auth tests PASS |
| `GET /api/auth/me` | Bearer JWT | authenticated UIN lookup | self | `auth:<uin>:auth:me` contract | generic auth/not-found | auth tests PASS |
| `POST /api/auth/panic-wipe` | Bearer JWT + CSRF | wipe uses authenticated UIN throughout | self | `auth:<uin>:auth:panic-wipe` contract | generic, idempotent | panic-wipe tests PASS |
| `GET /api/auth/health` | open | dependency health only | anonymous/operator | edge health bucket | no identifiers | route audit |
| `GET /api/contacts/` | Bearer JWT | `qListContactsForOwner WHERE c.owner_uin=$1` | self | `auth:<uin>:contacts:list` contract | generic auth/store error | two-user/no-actor test PASS |
| `POST /api/contacts/` | Bearer JWT + CSRF | actor from context; target is object only | self | `auth:<uin>:contacts:add` contract | target lookup maps to generic not-found/conflict | two-user/no-actor test PASS |
| `PUT /api/contacts/{target_uin}/accept` | Bearer JWT + CSRF | incoming edge is constrained by actor and target | request recipient | `auth:<uin>:contacts:accept` contract | generic not-found | two-user/no-actor test PASS |
| `PUT /api/contacts/{target_uin}/block` | Bearer JWT + CSRF | updates actor-owned edge only | self | `auth:<uin>:contacts:block` contract | generic status | two-user/no-actor test PASS |
| `DELETE /api/contacts/{target_uin}` | Bearer JWT + CSRF | deletes actor-owned edge only | self | `auth:<uin>:contacts:delete` contract | idempotent/generic | two-user/no-actor test PASS |
| `GET /api/keys/bundle/{uin}` | intentionally open | public Signal prekey bundle; consumes one OPK transactionally | anyone | rotating anonymous HMAC contract | `BUNDLE_NOT_FOUND` (public discovery is intentional) | key tests PASS |
| `POST /api/keys/bundle` | Bearer JWT | authenticated UIN; identity key must match registered key | self | `auth:<uin>:keys:bundle-write` contract | generic validation/conflict | no-actor test PASS |
| `POST /api/keys/prekeys` | Bearer JWT | insert under authenticated UIN | self | `auth:<uin>:keys:prekeys-write` contract | generic validation/store | no-actor test PASS |
| `GET /api/keys/prekeys/count` | Bearer JWT | count under authenticated UIN | self | `auth:<uin>:keys:prekeys-count` contract | generic auth/store | no-actor test PASS |
| `GET /api/keys/health` | open | dependency health only | anonymous/operator | edge health bucket | no identifiers | route audit |
| `GET /api/messages/history` | Bearer JWT | canonical `dm:min:max`; actor must be one member before Scylla query | either DM member | `auth:<uin>:messages:history` contract | malformed/foreign collapses to `403 NOT_A_MEMBER` | unrelated B test PASS |
| `GET /api/messages/group-history` | Bearer JWT | `isGroupMember(group_id, actor)` before Scylla query | current member | `auth:<uin>:messages:group-history` contract | nonexistent and nonmember both `403 NOT_A_MEMBER` | handler review/test suite PASS |
| `POST /api/groups/` | Bearer JWT | owner and initial admin are authenticated UIN | authenticated user | `auth:<uin>:groups:create` contract | generic validation/store | handler test suite PASS |
| `GET /api/groups/` | Bearer JWT | `qListGroupsForMember ... WHERE m.uin=$1` | current member | `auth:<uin>:groups:list` contract | empty list hides foreign groups | handler test suite PASS |
| `GET /api/groups/{group_id}/members` | Bearer JWT | `qGetGroupRole(group_id, actor)` before roster query | current member | `auth:<uin>:groups:members-list` contract | nonexistent/nonmember both 403 | handler test suite PASS |
| `POST /api/groups/{group_id}/members` | Bearer JWT | `qGetGroupRole(group_id, actor)='admin'` | admin | `auth:<uin>:groups:members-add` contract | nonexistent/nonadmin both 403 | handler test suite PASS |
| `DELETE /api/groups/{group_id}/members/{uin}` | Bearer JWT | self-leave, otherwise actor role must be admin | self or admin | `auth:<uin>:groups:members-remove` contract | generic role/membership errors | handler test suite PASS |
| `DELETE /api/groups/{group_id}` | Bearer JWT | atomic `DELETE ... WHERE id=$1 AND owner_uin=$2` | owner | `auth:<uin>:groups:delete` contract | nonexistent/not-owner both 404 | handler test suite PASS |
| `GET /api/presence/{uin}` | **open at service and Caddy** | requested UIN only; no relationship predicate | anyone | edge bucket only | offline sentinel hides existence imperfectly | **OPEN FINDING P-1** |
| `POST /api/presence/bulk` | **open at service and Caddy** | arbitrary requested UIN set | anyone | edge bucket only | offline sentinel | **OPEN FINDING P-1** |
| `POST /api/files/upload-url` | Bearer JWT | records generated UUID with authenticated owner in `file_objects` | self | `auth:<uin>:files:upload` contract | generic store/presign failure | no-actor test PASS |
| `POST /api/files/download-url` | Bearer JWT | owner-or-explicit-grantee `EXISTS` predicate before presign | recorded owner or grantee | `auth:<uin>:files:download` contract | missing and foreign both `404 OBJECT_NOT_FOUND` | unrelated B and grantee tests PASS |
| `POST /api/files/avatar-upload-url` | Bearer JWT | key is derived only from authenticated UIN | self | `auth:<uin>:files:avatar` contract | generic auth/store | no-actor test PASS |
| `POST /api/files/grants` | Bearer JWT | atomic `INSERT ... SELECT` succeeds only when actor owns object | owner | `auth:<uin>:files:grant` contract | missing and foreign both 404 | owner/B behavioral test PASS |
| `DELETE /api/files/grants` | Bearer JWT | delete is constrained by object, owner actor, and grantee | owner | `auth:<uin>:files:grant-revoke` contract | idempotent 204 | grant/revoke behavioral test PASS |
| `GET /ws` | Bearer access token in first WebSocket auth envelope; JWT verifier checks session epoch/revocation | sender UIN overwritten from authenticated client; DM receiver/group membership checks occur in router | authenticated sender/current member | edge connection bucket; service contract `auth:<uin>:ws:<envelope-type>` | generic close/error envelope | ws router/client tests PASS |

Health routes outside `/api` are not part of this matrix. Caddy's `/health`
short-circuits locally; individual service `/health` routes are reachable only
inside the deployment network except the two `/api/*/health` routes above.

## File ownership migration contract

`006_file_object_owners.sql` and `007_file_object_grants.sql` are fail-closed and
mounted as top-level PostgreSQL init scripts in Compose. New upload URL issuance records the
random UUID and authenticated owner before returning the URL. Download URL
issuance requires either that owner row or an explicit owner-created grantee row
in the database query. The direct-message client grants its intended recipient
before sending the encrypted attachment envelope and revokes the grant when
encryption or synchronous transport submission fails. Pre-existing MinIO
objects have no registry row and therefore become unavailable; an operator may
backfill only from a trusted ownership source. There is deliberately no
"allow legacy UUID" fallback because knowledge or guessing of an object key is
not authorization. Group attachments remain disabled in the UI; no implicit
group-wide grant is created.

## Rate-limit and edge privacy contract

Authenticated bucket format is generated by
`middleware.AuthenticatedRateLimitKey`: verified UIN plus a fixed action. The
anonymous login/register implementation accepts
`X-IceQ-RateLimit-Identity` only from Caddy and persists a daily rotating
HMAC-SHA-256 bucket. Redis keys contain neither raw IP nor User-Agent. The HMAC
secret is the mandatory high-entropy service JWT secret; rotation of that
secret also invalidates rate buckets.

Caddy may inspect `{remote_host}` transiently and forwards it only in the
dedicated header. It overwrites `X-Real-IP`/`X-Forwarded-For` with `iceq-edge`.
Filtered access logs delete all known remote-address fields plus User-Agent,
Authorization, and Cookie; `/ws` and message-history logging is skipped. The
dedicated header must never be added to log formats. Current Caddy edge zones
still use transient `{remote_host}` for defense in depth; application stores do
not receive or persist raw IP/UA.

## Open findings and limits

- **P-1 (high):** presence endpoints are publicly exposed and permit arbitrary
  UIN presence queries/enumeration. Fix requires a product decision (contacts
  only, group co-members, or explicit privacy setting) and DB-backed
  authorization; it was not silently changed in this slice.
- Authenticated UIN/action key generation is now shared and documented, but
  most service routes still rely on Caddy's transient edge zones rather than a
  Redis-backed per-action service middleware. Applying limits safely requires
  endpoint budgets and Redis wiring per service; the key contract prevents
  future raw network-identity persistence.
- Public key-bundle discovery is required for asynchronous Signal session
  setup and is intentionally not treated as private object access.
- File grants and WebSocket delivery are separate services, so rollback covers
  encryption and synchronous send submission failures, not a later negative or
  missing delivery acknowledgment. Durable ack-coupled grant cleanup remains a
  future cross-service transaction/outbox concern.
