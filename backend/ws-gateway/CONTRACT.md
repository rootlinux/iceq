# WS-Gateway — Panic-Wipe Contract

This document is the *contract* the ws-gateway must implement when
it lands (the gateway is built in a later step; this addendum defines
its panic-wipe behaviour so the auth-service can ship first).

## On every inbound message

After the gateway has verified the JWT (signature, type, expiry,
not blocklisted), it MUST check the per-user wipe key:

```
EXISTS jwt:blocklist:wipe:{uin}
```

If the key exists, the gateway closes the connection with WebSocket
close code `4403` and reason string `"account_wiped"`. The
connection MUST be closed even if the message is otherwise valid —
a wiped user is not allowed to send or receive anything, even a
heartbeat.

The check is O(1) — a single Redis EXISTS round trip. We deliberately
do not cache the result in-process: a wipe is rare but must take
effect immediately for *all* of the user's active connections, and a
per-process cache would mean each gateway process has its own view
of "is this user wiped". Stale-cache is a real bug here.

## On the connection upgrade

The gateway MAY short-circuit the upgrade by checking the wipe key
during token verification (i.e. before `Upgrade: websocket` is
returned to the client). This avoids a wasted round trip for a
client whose access token is valid but whose account is wiped.

The check is the same: `EXISTS jwt:blocklist:wipe:{uin}`. If true,
return `403 Forbidden` with body `{"error":"account_wiped","code":"WIPED"}`
and do NOT upgrade.

## Close code

- `4403` — account wiped. Client must clear local state and redirect
  to /login. No recovery.
- `4401` — token rejected (missing, expired, revoked, wrong type).
  Client should attempt refresh and reconnect.

The codes are part of the platform contract; see
[web/src/lib/wsCloseCodes.ts](../../web/src/lib/wsCloseCodes.ts).

## Implementation in Go (sketch)

```go
// In the message-read loop, after JWT verification:
ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
defer cancel()
wiped, err := deps.Redis.Exists(ctx, "jwt:blocklist:wipe:"+strconv.FormatInt(uin, 10)).Result()
if err != nil {
    // Fail-closed for this code path. A wipe detection
    // outage must not let a wiped user keep talking.
    log.Printf("[ws-gateway] wipe check failed for uin=%d: %v", uin, err)
    return
}
if wiped > 0 {
    ws.WriteControl(websocket.CloseMessage,
        websocket.FormatCloseMessage(4403, "account_wiped"),
        time.Now().Add(time.Second))
    return
}
```

## Why fail-closed on Redis outage

If the wipe check errors (Redis unreachable, network blip), the
gateway MUST close the connection anyway. The alternative — letting
the user continue during a Redis outage — would mean an attacker
who can DoS Redis could keep talking on a wiped account. Failing
closed is the correct security posture; the availability cost is
acceptable because Redis being unreachable is itself a P0 event.
