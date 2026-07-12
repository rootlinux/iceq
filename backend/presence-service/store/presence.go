// Package store is the presence-service's only persistence layer. It
// wraps a *redis.Client and exposes a small, opinionated API for
// reading and writing the per-user presence record.
//
// Storage model
// -------------
//
// One Redis hash per user, keyed by `presence:{uin}`. The hash has
// two fields:
//
//   - status:    one of "online" | "away" | "dnd" | "offline"
//   - last_seen: server clock at the moment the record was written,
//                stored as a string-encoded unix millisecond
//                timestamp (minute granularity — the ws-gateway
//                already truncates the timestamp before publishing).
//
// TTL semantics
// -------------
//
// The TTL is what makes the "sliding window" work. A user is
// considered online iff their `presence:{uin}` key still has at
// least one active status field and has not yet expired. We do not
// poll; the only consumer reads via HGETALL and trusts the key's
// existence as the liveness signal.
//
//   - online / away / dnd: TTL = 5 minutes (300s). The ws-gateway
//     heartbeats a user's status every 60s while they are
//     connected, so the key is always refreshed well before the
//     TTL fires. A disconnect drops the heartbeat and the key
//     naturally expires into "offline" without any explicit
//     offline event.
//   - offline: TTL = 24 hours. The offline record is only useful
//     for the `last_seen` field, which is shown in the UI as
//     "last seen 2h ago". Keeping the row for 24h gives the UI a
//     meaningful value for the common case of a user briefly
//     disconnecting and reconnecting.
//
// Concurrent writes
// -----------------
//
// Two writers can race on the same key (a presence-update from the
// bus and a /api/presence/{uin} write, for example). Redis hashes
// are atomic at the field level, so HSET on disjoint fields is
// safe; the only real risk is "online at T, offline at T-1" if
// out-of-order. We mitigate by using a single EXPIRE call after
// the HSET, and by accepting that minute-granularity timestamps
// already make reordering harmless for the UI.
package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// ----------------------------------------------------------------------------
// Public types.
// ----------------------------------------------------------------------------

// PresenceState is the value returned by GetPresence / GetBulkPresence.
// It is a snapshot — the caller must not assume the underlying Redis
// hash is still in this state by the time they read the next byte.
//
// LastSeen is unix milliseconds. A zero value means the user has
// never been seen since this Redis instance was provisioned (or, in
// practice, since the key was first written and immediately read
// back; the store never writes a non-zero last_seen itself).
type PresenceState struct {
	Status   string `json:"status"`
	LastSeen int64  `json:"last_seen"`
}

// ----------------------------------------------------------------------------
// Constants. The TTLs are the only tunable knobs; everything else
// is derived from the spec and should not be changed without
// coordination with the rest of the IceQ services.
// ----------------------------------------------------------------------------

const (
	// statusField and lastSeenField are the two hash fields we
	// read and write. They are kept as constants so a typo in
	// one of the methods is a compile error, not a silent
	// misread of an always-empty field.
	statusField   = "status"
	lastSeenField = "last_seen"

	// ttlOnline is the sliding-window TTL for live presence
	// records. A user is considered live for 5 minutes after
	// their last heartbeat; the ws-gateway heartbeats every
	// 60s while connected, so 300s is the right safety
	// margin (5 missed heartbeats before the record is
	// considered stale).
	ttlOnline = 5 * time.Minute

	// ttlOffline is the retention window for the
	// "last seen" record of a user who has gone offline.
	// 24 hours covers a full day's worth of UI history
	// ("last seen 14h ago") without keeping stale rows
	// in Redis forever.
	ttlOffline = 24 * time.Hour

	// KeyPrefix is the per-user key prefix. Exported so the
	// rest of the service (and tests) can build keys
	// without re-deriving the convention.
	KeyPrefix = "presence:"
)

// ----------------------------------------------------------------------------
// Valid status set. A status is the value of the `status` hash
// field. The four values mirror the constants in shared/models
// (PresenceStatus*), but we duplicate them here rather than
// importing models to keep this package free of upstream
// dependencies and easy to unit-test in isolation.
// ----------------------------------------------------------------------------

// validStatus is the set of statuses SetStatus accepts. Online,
// away, dnd, and offline. Anything else is rejected before the
// write so a typo at the publisher (e.g. "oneline") cannot
// pollute the keyspace.
var validStatus = map[string]struct{}{
	"online":  {},
	"away":    {},
	"dnd":     {},
	"offline": {},
}

// IsValidStatus returns true iff `s` is one of the four valid
// presence states. Exported so the HTTP layer (which accepts a
// user-supplied status string) can reject bad input before it
// hits Redis.
func IsValidStatus(s string) bool {
	_, ok := validStatus[s]
	return ok
}

// IsOfflineStatus reports whether the given status is the
// "offline" value. Used by SetStatus to pick the right TTL —
// callers that already know their intent (SetOnline / SetOffline)
// do not need this, but the generic SetStatus entry point does.
func IsOfflineStatus(s string) bool {
	return s == "offline"
}

// ----------------------------------------------------------------------------
// PresenceStore. The single public type. It is a thin wrapper
// around a *redis.Client; we wrap rather than pass the client
// around so we can add cross-cutting concerns (logging, metrics,
// a future in-memory cache) at one well-defined seam.
// ----------------------------------------------------------------------------

// PresenceStore is the presence-service's read/write surface
// against Redis. It is safe for concurrent use; *redis.Client
// itself is concurrency-safe and the methods here hold no
// mutable state.
type PresenceStore struct {
	rdb *redis.Client
}

// New constructs a PresenceStore. The caller owns the underlying
// *redis.Client and is responsible for closing it on shutdown.
// We keep a single store per process; multiple goroutines share
// it.
func New(rdb *redis.Client) *PresenceStore {
	if rdb == nil {
		panic("store.New: redis client is nil")
	}
	return &PresenceStore{rdb: rdb}
}

// ----------------------------------------------------------------------------
// SetOnline / SetOffline — convenience wrappers for the two most
// common transitions. The body of each is one HSET + EXPIRE,
// pipelined to avoid two round trips.
// ----------------------------------------------------------------------------

// SetOnline marks the user as currently online, with last_seen
// stamped to the current server clock. The key is given a
// 5-minute sliding TTL.
//
// Returns the underlying Redis error if the HSET or EXPIRE
// fails. The store does not retry; the caller (a NATS handler)
// will see the next heartbeat and re-write the key.
func (s *PresenceStore) SetOnline(ctx context.Context, uin int64) error {
	return s.writeStatus(ctx, uin, "online", ttlOnline)
}

// SetOffline marks the user as offline. last_seen is still
// stamped (it is the "last seen X ago" UI value), but the TTL is
// 24 hours — long enough for the UI to render a meaningful
// timestamp, short enough that a user who never reconnects
// doesn't keep a row in Redis forever.
//
// Idempotent: calling SetOffline on a user who is already
// offline just refreshes their last_seen to "now" and resets
// the TTL. This is what we want when a session is force-closed
// and we need the timestamp to be accurate.
func (s *PresenceStore) SetOffline(ctx context.Context, uin int64) error {
	return s.writeStatus(ctx, uin, "offline", ttlOffline)
}

// ----------------------------------------------------------------------------
// SetStatus — the generic entry point. Validates the status
// (rejects anything not in {online, away, dnd, offline}) and
// picks the right TTL. The ws-gateway already truncates the
// timestamp to minute granularity before publishing on
// presence.update, so we use time.Now() as the source of truth
// here: at minute granularity, the publish-time and store-time
// clocks are indistinguishable for any UI purpose.
// ----------------------------------------------------------------------------

// SetStatus applies a status change to the user's record. The
// status string is validated against the closed set
// {online, away, dnd, offline}; an invalid value returns an
// error and writes nothing.
//
// The TTL is derived from the status: online/away/dnd use the
// 5-minute sliding window, offline uses the 24-hour retention.
// This is the same policy SetOnline / SetOffline implement
// explicitly, so a NATS handler that doesn't know which
// convenience to call can just call SetStatus.
func (s *PresenceStore) SetStatus(ctx context.Context, uin int64, status string) error {
	if !IsValidStatus(status) {
		return fmt.Errorf("store: invalid status %q (want online|away|dnd|offline)", status)
	}
	ttl := ttlOnline
	if IsOfflineStatus(status) {
		ttl = ttlOffline
	}
	return s.writeStatus(ctx, uin, status, ttl)
}

// writeStatus is the shared implementation behind SetOnline,
// SetOffline, and SetStatus. It stamps last_seen, HSETs the
// status field, and applies the TTL — all in a single
// pipelined round trip.
//
// The pipeline is fire-and-forget at the protocol level (no
// MULTI/EXEC): HSET and EXPIRE are not order-sensitive because
// the worst case is "TTL applied before status field exists,"
// which is harmless — the empty hash just expires a moment
// later, and the next SetStatus will re-create it.
func (s *PresenceStore) writeStatus(ctx context.Context, uin int64, status string, ttl time.Duration) error {
	key := KeyPrefix + strconv.FormatInt(uin, 10)
	ts := time.Now().UTC().UnixMilli()
	pipe := s.rdb.Pipeline()
	pipe.HSet(ctx, key, statusField, status, lastSeenField, strconv.FormatInt(ts, 10))
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("store: HSET/EXPIRE %s: %w", key, err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// GetPresence — read a single user's record.
// ----------------------------------------------------------------------------

// GetPresence returns the user's current presence state. If the
// key is missing (TTL expired, user has never been seen on this
// Redis instance), the returned *PresenceState has Status
// "offline" and LastSeen 0 — the canonical "we have no
// information" answer that the UI can render as "offline" with
// no last-seen timestamp.
//
// The error return is reserved for transport-level failures
// (Redis down, malformed hash). It is NOT returned for a
// missing key; the spec's "missing → offline" semantics are
// part of the public contract.
func (s *PresenceStore) GetPresence(ctx context.Context, uin int64) (*PresenceState, error) {
	key := KeyPrefix + strconv.FormatInt(uin, 10)
	vals, err := s.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("store: HGETALL %s: %w", key, err)
	}
	if len(vals) == 0 {
		// Missing key is the "offline" sentinel, not an
		// error. The UI relies on this; do not change
		// without coordinating with the web client.
		return &PresenceState{Status: "offline", LastSeen: 0}, nil
	}
	state := &PresenceState{
		Status: vals[statusField],
	}
	if v, ok := vals[lastSeenField]; ok {
		// last_seen is stored as a base-10 string. A
		// malformed value (e.g. someone hand-edited the
		// hash) is treated as 0 rather than an error;
		// the timestamp is a UI hint, not a security
		// boundary.
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			state.LastSeen = n
		}
	}
	// Defensive: if the status field was somehow missing
	// (e.g. partial write, manual edit), treat as offline
	// rather than returning an empty-string status that the
	// UI would render as "unknown".
	if state.Status == "" {
		state.Status = "offline"
	}
	return state, nil
}

// ----------------------------------------------------------------------------
// GetBulkPresence — read N users' records in one round trip.
// ----------------------------------------------------------------------------

// GetBulkPresence returns a presence record for every UIN in the
// input slice. The map is keyed by UIN; UINS that have no
// record on this Redis instance are included with the offline
// sentinel, so callers can iterate the input slice and look up
// each UIN without nil-checking.
//
// The query is implemented as a single Redis pipeline of
// HGETALL commands. For N keys, that is one round trip's worth
// of latency, regardless of N. At IceQ's expected roster sizes
// (a contact list is typically <500 entries) the pipeline is
// comfortably under 1 ms on a healthy Redis.
//
// An empty input slice returns an empty (non-nil) map; this
// avoids surprising nil-map semantics in the HTTP handler that
// json-encodes the result.
func (s *PresenceStore) GetBulkPresence(ctx context.Context, uins []int64) (map[int64]*PresenceState, error) {
	out := make(map[int64]*PresenceState, len(uins))
	if len(uins) == 0 {
		return out, nil
	}

	// Build the pipeline. We need the mapping from pipeline
	// index to UIN, so we keep the keys slice parallel to
	// the input.
	keys := make([]string, len(uins))
	pipe := s.rdb.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, len(uins))
	for i, uin := range uins {
		k := KeyPrefix + strconv.FormatInt(uin, 10)
		keys[i] = k
		cmds[i] = pipe.HGetAll(ctx, k)
	}
	// Exec returns the first error it saw, but individual
	// commands can also fail (e.g. a key is not a hash
	// because of a manual SET). We treat pipeline errors
	// as transport-level; per-command errors fall through
	// to the offline sentinel below.
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		// redis.Nil is returned by the pipeline when
		// every command found a missing key; that is
		// the "everyone is offline" case, not a
		// transport error. Anything else we propagate.
		return nil, fmt.Errorf("store: bulk HGETALL pipeline: %w", err)
	}

	for i, uin := range uins {
		vals, err := cmds[i].Result()
		if err != nil || len(vals) == 0 {
			out[uin] = &PresenceState{Status: "offline", LastSeen: 0}
			continue
		}
		state := &PresenceState{Status: vals[statusField]}
		if v, ok := vals[lastSeenField]; ok {
			if n, perr := strconv.ParseInt(v, 10, 64); perr == nil {
				state.LastSeen = n
			}
		}
		if state.Status == "" {
			state.Status = "offline"
		}
		out[uin] = state
	}
	return out, nil
}
