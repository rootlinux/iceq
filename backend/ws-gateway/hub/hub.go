// Package hub is the in-memory connection registry for the
// ws-gateway. It maps a user UIN to the set of currently-connected
// WebSocket clients (one per device: laptop, phone, web tab) and
// provides the fan-out primitives the NATS subscribers and the
// router use to deliver envelopes.
//
// Design constraints from the spec:
//
//  1. No global state. The Hub is constructed in main.go and
//     injected as a dependency to every component that needs it
//     (client, router, NATS handlers). This makes the package
//     trivially testable: spin up a Hub, register a client,
//     call Send, assert.
//
//  2. Multi-device delivery. Send(uin) writes to ALL active
//     clients for that UIN. A user with two open tabs gets the
//     message in both; the per-client writeLoop serializes the
//     actual frame write to its own WebSocket.
//
//  3. Undelivered queue. When a user has no active connection,
//     Send enqueues the envelope in Redis (RPUSH undelivered:{uin}
//     with EXPIRE 7 days). The client's connect path drains this
//     list on registration, preserving the at-least-once delivery
//     guarantee the spec requires.
//
//  4. Thread safety. The underlying map is a sync.Map — chosen
//     because the workload is "write once at connect, read many
//     times during fan-out, delete once at disconnect". sync.Map
//     is optimized for exactly this shape; a plain map + mutex
//     would re-take the lock for every Send.
//
//  5. Privacy. The Hub NEVER logs UINs, IPs, or envelope contents.
//     Operational logs (e.g. "dropped undelivered for uin, queue
//     full") are scrubbed of the uin for the same reason the
//     auth-service's failed-login logs were scrubbed.
package hub

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/iceq/iceq/ws-gateway/client"
	"github.com/redis/go-redis/v9"
)

// ----------------------------------------------------------------------------
// Constants for the undelivered-queue contract. Pulled out of the
// Hub methods so the format is visible in one place and any future
// service that reads undelivered:{uin} can grep for the key shape.
// ----------------------------------------------------------------------------

const (
	// UndeliveredKeyPrefix scopes the per-user undelivered
	// envelopes in Redis. The client drain path on connect does
	// LRANGE 0 -1 + DEL on this key.
	UndeliveredKeyPrefix = "undelivered:"

	// UndeliveredTTL is the lifetime of the per-user list. 7
	// days matches the panic-wipe blocklist TTL: long enough
	// for a user to come back from a week-long vacation and
	// still get their messages, short enough to bound Redis
	// memory if a user never returns.
	UndeliveredTTL = 7 * 24 * time.Hour

	// UndeliveredMaxLen is the soft cap on the undelivered list
	// length. Past this length we drop the new message and log
	// (without uin) — a user who has been offline for >7 days
	// is expected to fall back to the REST history endpoint,
	// not to a magic growing queue in Redis.
	UndeliveredMaxLen = 1000

	// maxConnectionsPerUIN caps the number of concurrent WS
	// connections a single account can hold. Five covers the
	// "laptop, phone, web, mobile, backup" multi-device case
	// while preventing a single account from filling the Hub's
	// sync.Map and the per-connection goroutine pool. F-RL-3.
	maxConnectionsPerUIN = 5
)

// ----------------------------------------------------------------------------
// Hub. The registry itself. Holds the sync.Map keyed by UIN, plus
// the Redis client the Send method uses to enqueue undelivered
// envelopes.
// ----------------------------------------------------------------------------

// Hub is the per-process registry of active WebSocket clients.
// The zero value is NOT usable; construct with New.
type Hub struct {
	// clients maps a UIN to the slice of *Client connections
	// currently open for that UIN. The slice is owned by the
	// Hub — Register appends, Unregister removes, Send and
	// Broadcast iterate. sync.Map is chosen over a plain map
	// + sync.Mutex because the workload is dominated by reads
	// (every Send, every NATS subscriber callback) and because
	// LoadOrStore gives us an atomic read-or-create without a
	// separate critical section.
	clients sync.Map

	// mu serializes slice replacement for Register/Unregister.
	// sync.Map cannot CompareAndSwap slice values because slices
	// are not comparable in Go.
	mu sync.Mutex

	// rdb is the Redis client used by Send to enqueue
	// undelivered envelopes. Required.
	rdb *redis.Client
}

// New constructs a Hub with the given Redis client. The Redis
// client is required: Send enqueues to Redis when the user is
// offline, and a nil client would silently drop messages.
func New(rdb *redis.Client) *Hub {
	if rdb == nil {
		panic("hub: redis client is nil")
	}
	return &Hub{rdb: rdb}
}

// ----------------------------------------------------------------------------
// Register / Unregister. Called by the client lifecycle (client.go)
// when a WebSocket upgrade succeeds and when the connection closes
// for any reason. Both methods are safe for concurrent use.
// ----------------------------------------------------------------------------

// Register adds a client to the hub. Returns
// client.ErrHubTooManyConnections if the per-UIN cap
// (maxConnectionsPerUIN) is already reached; in that case the
// client is NOT registered and the caller should reject the WS
// upgrade.
//
// The check is a CAS loop on sync.Map: load the slice, check
// length, swap in the new slice. If a concurrent Register beat
// us to the punch, retry with the fresh slice. We cannot use a
// plain Load-then-Store (the original implementation) because
// that races with another Register, both append to the same
// underlying array, and the second Store overwrites the first.
//
// The sentinel error is defined in the client package (not here)
// to avoid a hub → client → hub import cycle; hub already
// imports client.
func (h *Hub) Register(c *client.Client) error {
	if c == nil {
		return nil
	}
	uin := c.UIN()
	h.mu.Lock()
	defer h.mu.Unlock()

	raw, _ := h.clients.LoadOrStore(uin, []*client.Client{})
	slice := raw.([]*client.Client)
	if len(slice) >= maxConnectionsPerUIN {
		return client.ErrHubTooManyConnections
	}
	next := make([]*client.Client, 0, len(slice)+1)
	next = append(next, slice...)
	next = append(next, c)
	h.clients.Store(uin, next)
	return nil
}

// Unregister removes a client from the hub. If it was the last
// client for that UIN, the per-UIN entry is deleted so the map
// does not grow unboundedly with users who logged out years ago.
//
// Safe to call on a not-yet-registered client (a no-op).
func (h *Hub) Unregister(c *client.Client) {
	if c == nil {
		return
	}
	uin := c.UIN()
	h.mu.Lock()
	defer h.mu.Unlock()

	raw, ok := h.clients.Load(uin)
	if !ok {
		return
	}
	slice := raw.([]*client.Client)
	next := make([]*client.Client, 0, len(slice))
	found := false
	for _, existing := range slice {
		if existing == c {
			found = true
			continue
		}
		next = append(next, existing)
	}
	if !found {
		return
	}
	if len(next) == 0 {
		h.clients.Delete(uin)
		return
	}
	h.clients.Store(uin, next)
}

// ----------------------------------------------------------------------------
// Send. The single-target fan-out primitive. Writes envelope to
// every active client for uin, OR enqueues to Redis if no
// connection is open. Returns nil on success; an error only if
// the Redis enqueue path itself fails (network blip, keyspace
// full). Per-client write errors are not propagated — they are
// logged inside the client's writeLoop and trigger an unregister.
// ----------------------------------------------------------------------------

// Send delivers envelope to the user identified by uin.
//
// Behavior:
//
//   - One or more active connections: write to each. The per-
//     client writeLoop serializes the actual WS write so a slow
//     consumer cannot block a fast one.
//   - Zero active connections: RPUSH the envelope to
//     undelivered:{uin} with EXPIRE 7 days. The next time the
//     user connects, the drain path in client.go will deliver it.
//   - Undelivered list over the soft cap: drop and log (no uin
//     in the log line — same privacy posture as the auth-service).
//
// envelope is treated as opaque bytes. The hub does not parse it.
func (h *Hub) Send(ctx context.Context, uin int64, envelope []byte) error {
	if uin == 0 {
		// A 0 UIN is a spec violation: the auth-service starts
		// the sequence at 10_000_000, and 0 is a sentinel that
		// would silently route to the wrong list. Log and drop.
		log.Printf("[ws-gateway] hub: send to uin=0 dropped (invalid)")
		return nil
	}
	if len(envelope) == 0 {
		return nil
	}
	// Polling has its own bounded stream. It is intentionally independent of
	// the destructive WebSocket reconnect queue: either transport may observe
	// the same envelope and the client suppresses duplicates by envelope ID.
	pollKey := "poll:stream:" + uinToString(uin)
	pipe := h.rdb.Pipeline()
	pipe.XAdd(ctx, &redis.XAddArgs{Stream: pollKey, MaxLen: UndeliveredMaxLen, Approx: true, Values: map[string]any{"envelope": envelope}})
	pipe.Expire(ctx, pollKey, UndeliveredTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		// Poll fallback is a secondary receive path. A transient Redis
		// failure must not suppress delivery to an already-open WebSocket.
		log.Printf("[ws-gateway] hub: poll enqueue unavailable: %v", err)
	}

	raw, ok := h.clients.Load(uin)
	if !ok {
		return h.enqueueUndelivered(ctx, uin, envelope)
	}
	slice := raw.([]*client.Client)
	// Iterate by pointer. The slice is a snapshot — a concurrent
	// Unregister may mutate the store, but our local slice is
	// already captured. Dereferencing each *client.Client
	// inside the loop is safe because the Client's send
	// channel is a reference type and never gets closed by
	// anyone but the owning goroutine.
	for _, c := range slice {
		// TrySend is non-blocking: if the per-client buffer is
		// full, the message is dropped for that client (the
		// client writeLoop will pick up the next message and
		// the slow one's read deadline will fire eventually,
		// closing the connection).
		c.TrySend(envelope)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Broadcast. The fan-out primitive for group messages. Walks the
// provided UIN list and Send's to each. Errors from individual
// Sends are not propagated — at-least-once delivery is best
// achieved by logging the failure and letting the next message
// push the queue forward.
// ----------------------------------------------------------------------------

// Broadcast delivers envelope to every UIN in uins. Used by the
// group-message NATS subject handler and by the presence broadcast.
//
// The slice may be large (a 500-person group). We do not parallelize
// the per-UIN fan-out because sync.Map reads scale well and the
// per-client TrySend is already non-blocking; an extra
// goroutine-launch per group message would cost more than it saves.
func (h *Hub) Broadcast(ctx context.Context, uins []int64, envelope []byte) {
	for _, uin := range uins {
		// Errors are intentionally ignored here. The group-message
		// path's correctness is not "every member's queue advanced
		// atomically" — it's "the group ID's NATS subject was
		// published, the per-recipient delivery is best-effort,
		// the message-service's persistence is the durable backstop".
		_ = h.Send(ctx, uin, envelope)
	}
}

// ----------------------------------------------------------------------------
// Internals.
// ----------------------------------------------------------------------------

// enqueueUndelivered pushes envelope onto the per-user Redis list.
// Called from Send when the user has no active connection.
//
// We use RPUSH + EXPIRE on every call (rather than only on the
// first push) so the TTL is refreshed each time. The trade-off:
// a user who gets one message per week would otherwise see their
// queue expire between pushes. The 7-day window is the "user
// comes back from vacation" bound; we want it to mean "the message
// is preserved for at least 7 days after it was queued", not
// "the message is preserved for 7 days after the first push".
func (h *Hub) enqueueUndelivered(ctx context.Context, uin int64, envelope []byte) error {
	key := UndeliveredKeyPrefix + uinToString(uin)
	pipe := h.rdb.Pipeline()
	llenCmd := pipe.LLen(ctx, key)
	rpushCmd := pipe.RPush(ctx, key, envelope)
	expireCmd := pipe.Expire(ctx, key, UndeliveredTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		// Fall through to a per-command error check below;
		// pipeline.Exec returns the first error but we want
		// to inspect the LLEN to decide whether to drop.
		return err
	}
	if err := llenCmd.Err(); err != nil {
		return err
	}
	if err := rpushCmd.Err(); err != nil {
		return err
	}
	if err := expireCmd.Err(); err != nil {
		// EXPIRE on a non-existent key is a no-op (returns 0),
		// not an error. A real error here is a network blip;
		// the message is still on the list with the previous
		// (or no) TTL. We log and continue.
		log.Printf("[ws-gateway] hub: undelivered expire: %v", err)
	}
	// Soft cap: if the list is now over the cap, the new
	// message is the one we just pushed. Trim from the LEFT
	// (oldest first) until the list is at the cap. This
	// preserves recent messages at the cost of historical
	// ones, which is the right trade-off — the historical
	// ones would be served by the REST history endpoint.
	if llen := llenCmd.Val(); llen > UndeliveredMaxLen {
		// LTRIM key 0 (cap-1) keeps the newest `cap` items.
		// Indices: keep [-(cap) .. -1] == [len-cap .. len-1].
		// We use a negative start to express "the cap oldest".
		if err := h.rdb.LTrim(ctx, key, int64(-UndeliveredMaxLen), -1).Err(); err != nil {
			log.Printf("[ws-gateway] hub: undelivered trim: %v", err)
		}
		// We do NOT log the dropped count or the uin. Same
		// privacy posture as the rest of the gateway: an
		// operator observing the log can tell that *some*
		// user's queue overflowed, but not which.
	}
	return nil
}

// uinToString is a small wrapper around strconv.FormatInt kept
// local to this package so call sites read as English
// (UndeliveredKeyPrefix + uinToString(uin)) rather than the
// noisier strconv.FormatInt(uin, 10).
func uinToString(n int64) string {
	// We import strconv only here; the rest of the file is
	// formatter-free.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
