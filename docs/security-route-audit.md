# Security Route Audit

Audit date: 2026-07-16. Scope: every repository route mounted below `/api` or
`/ws`. For authenticated object routes, `actor` means `middleware.GetUIN`
populated by `BearerAuth`; refresh instead derives its actor from the verified
refresh JWT. A body, path, or query UIN is never accepted as an actor.

## Route matrix

| Route | Authentication source | Object / authorization predicate | Allowed role | Rate-limit key | Uniform public failure | Evidence |
|---|---|---|---|---|---|---|
| `POST /api/auth/register` | open; edge identity header | new user; unique conflicts intentionally collapse | anonymous | rotating HMAC(edge identity, `register`), 3/min | generic `USER_EXISTS`; limiter fails closed | handler DB-double role/ownership tests PASS |
| `POST /api/auth/login` | open; edge identity header | `qFindUserByIdentifier`; identifier existence hidden by decoy hash | anonymous | rotating HMAC(edge identity, `login`), 5/min | `INVALID_CREDENTIALS`; limiter fails closed | handler DB-double role/ownership tests PASS |
| `POST /api/auth/refresh` | refresh JWT from JSON or HttpOnly cookie + CSRF | verify JWT first, then limit verified UIN before row lookup/rotation | token owner | enforced Redis `auth:<uin>:auth:refresh`, 5/min | invalid token never consumes bucket; limiter 429/503 uniform | refresh limiter behavioral unit tests PASS |
| `POST /api/auth/logout` | Bearer access JWT + CSRF | revokes access JTI, bumps actor epoch, deletes actor refresh rows | token owner | enforced Redis `auth:<uin>:auth:logout`, 10/min | generic token errors | auth unit tests PASS |
| `GET /api/auth/settings` | Bearer JWT | `qGetSettings WHERE uin=$1` | self | enforced Redis `auth:<uin>:auth:settings:read`, 60/min | generic auth/not-found | auth unit tests PASS |
| `PUT /api/auth/settings` | Bearer JWT + CSRF | `qUpsertSettings`, actor UIN | self | enforced Redis `auth:<uin>:auth:settings:write`, 10/min | generic validation/auth | auth unit tests PASS |
| `GET /api/auth/me` | Bearer JWT | authenticated UIN lookup | self | enforced Redis `auth:<uin>:auth:me`, 60/min | generic auth/not-found | auth unit tests PASS |
| `POST /api/auth/panic-wipe` | Bearer JWT + CSRF | wipe uses authenticated UIN throughout | self | enforced Redis `auth:<uin>:auth:panic-wipe`, 3/hour | generic, retry-safe handler | panic-wipe unit tests PASS |
| `GET /api/auth/health` | open | dependency health only | anonymous/operator | edge health bucket | no identifiers | route audit |
| `GET /api/contacts/` | Bearer JWT | `qListContactsForOwner WHERE c.owner_uin=$1` | self | enforced Redis `auth:<uin>:contacts:list`, 60/min | generic auth/store error | handler DB-double actor-scope tests PASS |
| `POST /api/contacts/` | Bearer JWT + CSRF | actor from context; target is object only | self | enforced Redis `auth:<uin>:contacts:add`, 30/min | target lookup maps to generic not-found/conflict | handler DB-double two-user tests PASS |
| `PUT /api/contacts/{target_uin}/accept` | Bearer JWT + CSRF | incoming edge is constrained by actor and target | request recipient | enforced Redis `auth:<uin>:contacts:accept`, 30/min | generic not-found | handler DB-double two-user tests PASS |
| `PUT /api/contacts/{target_uin}/block` | Bearer JWT + CSRF | updates actor-owned edge only | self | enforced Redis `auth:<uin>:contacts:block`, 30/min | generic status | handler DB-double two-user tests PASS |
| `DELETE /api/contacts/{target_uin}` | Bearer JWT + CSRF | deletes actor-owned edge only | self | enforced Redis `auth:<uin>:contacts:remove`, 30/min | idempotent/generic | handler DB-double two-user tests PASS |
| `GET /api/keys/bundle/{uin}` | intentionally open | limiter runs before public Signal bundle/OPK consumption | anyone | rotating HMAC(edge identity, `key-bundle`), 30/min | limiter fails closed 503 or 429 before store call | anonymous limiter behavioral unit tests PASS |
| `POST /api/keys/bundle` | Bearer JWT | authenticated UIN; identity key must match registered key | self | enforced Redis `auth:<uin>:keys:bundle:upload`, 10/min | generic validation/conflict | actor-scope unit test PASS |
| `POST /api/keys/prekeys` | Bearer JWT | insert under authenticated UIN | self | enforced Redis `auth:<uin>:keys:prekeys:add`, 20/min | generic validation/store | actor-scope unit test PASS |
| `GET /api/keys/prekeys/count` | Bearer JWT | count under authenticated UIN | self | enforced Redis `auth:<uin>:keys:prekeys:count`, 60/min | generic auth/store | actor-scope unit test PASS |
| `GET /api/keys/health` | open | dependency health only | anonymous/operator | edge health bucket | no identifiers | route audit |
| `GET /api/messages/history` | Bearer JWT | canonical `dm:min:max`; actor must be one member before Scylla query | either DM member | enforced Redis `auth:<uin>:messages:history`, 60/min | missing/prefix errors 400; invalid canonical membership uniformly 403 | foreign/noncanonical unit tests PASS |
| `GET /api/messages/group-history` | Bearer JWT | `isGroupMember(group_id, actor)` before Scylla query | current member | enforced Redis `auth:<uin>:messages:group-history`, 60/min | nonexistent and nonmember both `403 NOT_A_MEMBER` | handler DB-double membership tests PASS |
| `POST /api/groups/` | Bearer JWT | owner and initial admin are authenticated UIN | authenticated user | enforced Redis `auth:<uin>:groups:create`, 20/min | generic validation/store | handler DB-double role/ownership tests PASS |
| `GET /api/groups/` | Bearer JWT | `qListGroupsForMember ... WHERE m.uin=$1` | current member | enforced Redis `auth:<uin>:groups:list`, 60/min | empty list hides foreign groups | handler DB-double role/ownership tests PASS |
| `GET /api/groups/{group_id}/members` | Bearer JWT | `qGetGroupRole(group_id, actor)` before roster query | current member | enforced Redis `auth:<uin>:groups:members:list`, 60/min | nonexistent/nonmember both 403 | handler DB-double role/ownership tests PASS |
| `POST /api/groups/{group_id}/members` | Bearer JWT | `qGetGroupRole(group_id, actor)='admin'` | admin | enforced Redis `auth:<uin>:groups:members:add`, 30/min | nonexistent/nonadmin both 403 | handler DB-double role/ownership tests PASS |
| `DELETE /api/groups/{group_id}/members/{uin}` | Bearer JWT | self-leave, otherwise actor role must be admin | self or admin | enforced Redis `auth:<uin>:groups:members:remove`, 30/min | generic role/membership errors | handler DB-double role/ownership tests PASS |
| `DELETE /api/groups/{group_id}` | Bearer JWT | atomic `DELETE ... WHERE id=$1 AND owner_uin=$2` | owner | enforced Redis `auth:<uin>:groups:delete`, 10/min | nonexistent/not-owner both 404 | handler DB-double role/ownership tests PASS |
| `GET /api/presence/{uin}` | Bearer JWT | target must be self or an accepted contact of actor | self or accepted contact | enforced Redis `auth:<uin>:presence:read`, 120/min | unrelated and nonexistent both identical 404; Redis presence store is not queried | handler two-user tests with dependency doubles PASS |
| `POST /api/presence/bulk` | Bearer JWT | query authorizes each target as self/accepted contact before Redis read | self and accepted contacts only | enforced Redis `auth:<uin>:presence:bulk`, 30/min | unrelated/nonexistent entries are uniformly omitted | handler two-user tests with dependency doubles PASS |
| `POST /api/files/upload-url` | Bearer JWT | records generated UUID with authenticated owner in `file_objects` | self | enforced Redis `auth:<uin>:files:upload`, 30/min | generic store/presign failure | handler unit tests PASS |
| `POST /api/files/download-url` | Bearer JWT | owner-or-explicit-grantee `EXISTS` predicate before presign | recorded owner or grantee | enforced Redis `auth:<uin>:files:download`, 60/min | missing and foreign both `404 OBJECT_NOT_FOUND` | fake-registry authorization unit tests PASS |
| `POST /api/files/avatar-upload-url` | Bearer JWT | key is derived only from authenticated UIN | self | enforced Redis `auth:<uin>:files:avatar-upload`, 10/min | generic auth/store | handler unit tests PASS |
| `POST /api/files/grants` | Bearer JWT | atomic `INSERT ... SELECT` succeeds only when actor owns object | owner | enforced Redis `auth:<uin>:files:grant`, 30/min | missing and foreign both 404 | fake-registry owner/B unit tests PASS |
| `DELETE /api/files/grants` | Bearer JWT | delete is constrained by object, owner actor, and grantee | owner | enforced Redis `auth:<uin>:files:grant:revoke`, 30/min | foreign/missing uniformly 404; grant remains | fake-registry foreign-owner unit test PASS |
| `GET /ws` | Bearer access token in first WebSocket auth envelope; JWT verifier checks session epoch/revocation | sender UIN overwritten from authenticated client; canonical DM ID and group membership checks occur in router | authenticated sender/current member | edge 10 upgrades/min plus enforced Redis `auth:<uin>:ws:connect` 20/min and `ws:frame` 30/min | generic close/error envelope | WS auth/routing unit tests PASS |

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

## Enforced rate limits and edge privacy contract

Authenticated routes use the Redis-backed
`middleware.NewAuthenticatedRateLimit` after BearerAuth. It atomically consumes
an explicit per-route budget keyed by `AuthenticatedRateLimitKey`: verified UIN
plus a fixed action. Redis failure denies HTTP requests with 503; exhaustion is
429 with `Retry-After`. WebSocket authentication consumes a 20/minute
`ws:connect` bucket and every accepted client frame consumes a 30/minute
`ws:frame` bucket; limiter failure closes the connection fail-safe. Auth,
contacts, authenticated key routes, message history, groups, presence,
upload/download/avatar, and file grant/revoke routes have explicit service-side
budgets. Refresh verifies its refresh JWT before consuming the verified UIN's
bucket. The public bundle route uses the same anonymous rotating-HMAC pattern as
login/register before it can consume an OPK. The anonymous routes trust the
deployment edge to overwrite `X-IceQ-RateLimit-Identity` and persists a daily rotating
HMAC-SHA-256 bucket. Redis keys contain neither raw IP nor User-Agent. The HMAC
secret is the mandatory high-entropy service JWT secret; rotation of that
secret also invalidates rate buckets.

Caddy may inspect `{remote_host}` transiently and forwards it only in the
dedicated header. It overwrites `X-Real-IP`/`X-Forwarded-For` with `iceq-edge`
and strips upstream User-Agent. Its configured filter deletes `remote_addr`,
`remote_ip`, `client_ip`, User-Agent, Authorization, and Cookie;
`/ws` and message-history logging is skipped. The
dedicated header must never be added to log formats. Current Caddy edge zones
still use transient `{remote_host}` for defense in depth; application stores
persist only HMAC buckets, never the raw identity or User-Agent.

## Open findings and limits
- Public key-bundle discovery is required for asynchronous Signal session
  setup and is intentionally not treated as private object access.
- File grants and WebSocket delivery are separate services, so rollback covers
  encryption and synchronous send submission failures, not a later negative or
  missing delivery acknowledgment. Durable ack-coupled grant cleanup remains a
  future cross-service transaction/outbox concern.
