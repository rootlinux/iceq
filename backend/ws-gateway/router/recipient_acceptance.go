package router

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrInvalidAcceptance   = errors.New("invalid recipient acceptance")
	ErrAcceptanceExpired   = errors.New("recipient acceptance expired")
	ErrAcceptanceQueueFull = errors.New("recipient acceptance queue full")
)

const recipientAcceptanceMaxActive = 1000

type RecipientAcceptanceScope struct {
	recipientUIN int64
	seenScope    string
}

func DirectRecipientScope(recipientUIN int64) (RecipientAcceptanceScope, error) {
	if recipientUIN <= 0 {
		return RecipientAcceptanceScope{}, fmt.Errorf("%w: recipient_uin must be positive", ErrInvalidAcceptance)
	}
	return RecipientAcceptanceScope{recipientUIN: recipientUIN, seenScope: "direct"}, nil
}

func GroupMemberScope(groupID string, recipientUIN int64) (RecipientAcceptanceScope, error) {
	if recipientUIN <= 0 || strings.TrimSpace(groupID) == "" {
		return RecipientAcceptanceScope{}, fmt.Errorf("%w: group_id and positive recipient_uin are required", ErrInvalidAcceptance)
	}
	sum := sha256.Sum256([]byte(groupID))
	return RecipientAcceptanceScope{recipientUIN: recipientUIN, seenScope: "group:" + hex.EncodeToString(sum[:16])}, nil
}

// AcceptanceQueueKey is an ordered index of record references. It contains no ciphertext.
func AcceptanceQueueKey(scope RecipientAcceptanceScope) string {
	return acceptancePrefix(scope) + ":index"
}

type RecipientAcceptance struct {
	Scope     RecipientAcceptanceScope
	MessageID string
	Envelope  []byte
	ExpiresAt *time.Time
}
type AcceptedEnvelope struct {
	StreamID  string
	MessageID string
	Envelope  []byte
	Scope     string
}
type RecipientAcceptanceStore struct {
	rdb *redis.Client
	now func() time.Time
}

func NewRecipientAcceptanceStore(rdb *redis.Client) *RecipientAcceptanceStore {
	if rdb == nil {
		panic("recipient acceptance: redis client is nil")
	}
	return &RecipientAcceptanceStore{rdb: rdb, now: time.Now}
}

var acceptRecipientScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
local refs = redis.call('ZRANGE', KEYS[1], 0, -1)
for _, ref in ipairs(refs) do
  if redis.call('EXISTS', ref) == 0 then redis.call('ZREM', KEYS[1], ref) end
end
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[5]) then return -1 end
local seq = redis.call('INCR', KEYS[4])
redis.call('HSET', KEYS[3], 'message_id', ARGV[1], 'envelope', ARGV[2], 'scope', ARGV[3], 'seq', seq, 'expires_at', ARGV[4])
redis.call('SET', KEYS[2], '1')
if ARGV[4] ~= 'off' then
  redis.call('PEXPIREAT', KEYS[3], ARGV[4])
  redis.call('PEXPIREAT', KEYS[2], ARGV[4])
end
redis.call('ZADD', KEYS[1], seq, KEYS[3])
local live = redis.call('ZRANGE', KEYS[1], 0, -1)
local hasOff = false
local maxExpiry = 0
for _, ref in ipairs(live) do
  local expiry = redis.call('HGET', ref, 'expires_at')
  if not expiry or expiry == 'off' then hasOff = true else maxExpiry = math.max(maxExpiry, tonumber(expiry)) end
end
if hasOff then
  redis.call('PERSIST', KEYS[1]); redis.call('PERSIST', KEYS[4])
elseif #live == 0 then
  redis.call('DEL', KEYS[1]); redis.call('DEL', KEYS[4])
else
  redis.call('PEXPIREAT', KEYS[1], maxExpiry); redis.call('PEXPIREAT', KEYS[4], maxExpiry)
end
return 1
`)

func (s *RecipientAcceptanceStore) Accept(ctx context.Context, a RecipientAcceptance) (bool, error) {
	if a.Scope.recipientUIN <= 0 || a.Scope.seenScope == "" || strings.TrimSpace(a.MessageID) == "" || len(a.Envelope) == 0 {
		return false, ErrInvalidAcceptance
	}
	expires := "off"
	if a.ExpiresAt != nil {
		if !a.ExpiresAt.After(s.now()) {
			return false, ErrAcceptanceExpired
		}
		expires = strconv.FormatInt(a.ExpiresAt.UnixMilli(), 10)
	}
	result, err := acceptRecipientScript.Run(ctx, s.rdb, []string{
		AcceptanceQueueKey(a.Scope), acceptanceSeenKey(a.Scope, a.MessageID), acceptanceRecordKey(a.Scope, a.MessageID), acceptanceSequenceKey(a.Scope),
	}, a.MessageID, a.Envelope, a.Scope.seenScope, expires, recipientAcceptanceMaxActive).Int64()
	if err != nil {
		return false, err
	}
	if result == -1 {
		return false, ErrAcceptanceQueueFull
	}
	return result == 1, nil
}

var readAcceptedScript = redis.NewScript(`
local refs = redis.call('ZRANGEBYSCORE', KEYS[1], '(' .. ARGV[1], '+inf')
local out = {}
local limit = tonumber(ARGV[2])
for _, ref in ipairs(refs) do
  local values = redis.call('HMGET', ref, 'seq', 'message_id', 'envelope', 'scope')
  if not values[1] then
    redis.call('ZREM', KEYS[1], ref)
  elseif limit == 0 or (#out / 4) < limit then
    for _, value in ipairs(values) do table.insert(out, value) end
  end
end
local live = redis.call('ZRANGE', KEYS[1], 0, -1)
if #live == 0 then redis.call('DEL', KEYS[1]); redis.call('DEL', KEYS[2]) end
return out
`)

var drainAcceptedScript = redis.NewScript(`
local refs = redis.call('ZRANGEBYSCORE', KEYS[1], '(' .. ARGV[1], '+inf')
local out = {}
local limit = tonumber(ARGV[2])
for _, ref in ipairs(refs) do
  local values = redis.call('HMGET', ref, 'seq', 'message_id', 'envelope', 'scope')
  if not values[1] then
    redis.call('ZREM', KEYS[1], ref)
  elseif limit == 0 or (#out / 4) < limit then
    for _, value in ipairs(values) do table.insert(out, value) end
    redis.call('ZREM', KEYS[1], ref)
    redis.call('DEL', ref)
  end
end
local live = redis.call('ZRANGE', KEYS[1], 0, -1)
local hasOff = false
local maxExpiry = 0
for _, ref in ipairs(live) do
  local expiry = redis.call('HGET', ref, 'expires_at')
  if not expiry or expiry == 'off' then hasOff = true else maxExpiry = math.max(maxExpiry, tonumber(expiry)) end
end
if hasOff then redis.call('PERSIST', KEYS[1]); redis.call('PERSIST', KEYS[2])
elseif #live == 0 then redis.call('DEL', KEYS[1]); redis.call('DEL', KEYS[2])
else redis.call('PEXPIREAT', KEYS[1], maxExpiry); redis.call('PEXPIREAT', KEYS[2], maxExpiry) end
return out
`)

// ReadAcceptedAfter returns live records ordered after the durable sequence cursor.
// An empty cursor starts at the beginning; callers may persist the returned StreamID.
func (s *RecipientAcceptanceStore) ReadAcceptedAfter(ctx context.Context, scope RecipientAcceptanceScope, after string, count int64) ([]AcceptedEnvelope, error) {
	return s.readOrDrain(ctx, scope, after, count, false)
}

// DrainAccepted atomically returns and removes live records. A crash before this
// operation replays the record; after success the capacity is immediately reusable.
func (s *RecipientAcceptanceStore) DrainAccepted(ctx context.Context, scope RecipientAcceptanceScope, after string, count int64) ([]AcceptedEnvelope, error) {
	return s.readOrDrain(ctx, scope, after, count, true)
}

var ackAcceptedScript = redis.NewScript(`
local wanted = {}
for i=1,#ARGV do wanted[ARGV[i]] = true end
local refs = redis.call('ZRANGE', KEYS[1], 0, -1)
local removed = 0
for _, ref in ipairs(refs) do
  if redis.call('EXISTS', ref) == 0 then
    redis.call('ZREM', KEYS[1], ref)
  else
    local id = redis.call('HGET', ref, 'message_id')
    if wanted[id] then
      redis.call('ZREM', KEYS[1], ref)
      redis.call('DEL', ref)
      removed = removed + 1
    end
  end
end
local live = redis.call('ZRANGE', KEYS[1], 0, -1)
local hasOff = false
local maxExpiry = 0
for _, ref in ipairs(live) do
  local expiry = redis.call('HGET', ref, 'expires_at')
  if not expiry or expiry == 'off' then hasOff = true else maxExpiry = math.max(maxExpiry, tonumber(expiry)) end
end
if hasOff then redis.call('PERSIST', KEYS[1]); redis.call('PERSIST', KEYS[2])
elseif #live == 0 then redis.call('DEL', KEYS[1]); redis.call('DEL', KEYS[2])
else redis.call('PEXPIREAT', KEYS[1], maxExpiry); redis.call('PEXPIREAT', KEYS[2], maxExpiry) end
return removed
`)

// AckRecipient removes only payload records the authenticated recipient has
// durably processed. Seen markers remain, so producer redelivery is a no-op.
func (s *RecipientAcceptanceStore) AckRecipient(ctx context.Context, recipientUIN int64, messageIDs []string) (int64, error) {
	scope, err := DirectRecipientScope(recipientUIN)
	if err != nil || len(messageIDs) == 0 {
		return 0, err
	}
	args := make([]any, 0, len(messageIDs))
	for _, id := range messageIDs {
		if strings.TrimSpace(id) == "" {
			return 0, ErrInvalidAcceptance
		}
		args = append(args, id)
	}
	return ackAcceptedScript.Run(ctx, s.rdb, []string{AcceptanceQueueKey(scope), acceptanceSequenceKey(scope)}, args...).Int64()
}

// ReadAccepted preserves the older poll-facing shape. start is a sequence cursor;
// "-" and an empty string mean the beginning. stop is retained for compatibility.
func (s *RecipientAcceptanceStore) ReadAccepted(ctx context.Context, scope RecipientAcceptanceScope, start, _ string, count int64) ([]AcceptedEnvelope, error) {
	if start == "-" {
		start = ""
	}
	return s.ReadAcceptedAfter(ctx, scope, start, count)
}

func (s *RecipientAcceptanceStore) readOrDrain(ctx context.Context, scope RecipientAcceptanceScope, after string, count int64, drain bool) ([]AcceptedEnvelope, error) {
	if scope.recipientUIN <= 0 || scope.seenScope == "" || count < 0 {
		return nil, ErrInvalidAcceptance
	}
	if after == "" {
		after = "-inf"
	} else if _, err := strconv.ParseUint(after, 10, 64); err != nil {
		return nil, ErrInvalidAcceptance
	}
	script := readAcceptedScript
	if drain {
		script = drainAcceptedScript
	}
	values, err := script.Run(ctx, s.rdb, []string{AcceptanceQueueKey(scope), acceptanceSequenceKey(scope)}, after, count).Slice()
	if err != nil {
		return nil, err
	}
	if len(values)%4 != 0 {
		return nil, fmt.Errorf("recipient acceptance: corrupt read result")
	}
	out := make([]AcceptedEnvelope, 0, len(values)/4)
	for i := 0; i < len(values); i += 4 {
		out = append(out, AcceptedEnvelope{StreamID: redisValue(values[i]), MessageID: redisValue(values[i+1]), Envelope: []byte(redisValue(values[i+2])), Scope: redisValue(values[i+3])})
	}
	return out, nil
}

func acceptancePrefix(scope RecipientAcceptanceScope) string {
	return "poll:{" + strconv.FormatInt(scope.recipientUIN, 10) + "}"
}
func acceptanceSequenceKey(scope RecipientAcceptanceScope) string {
	return acceptancePrefix(scope) + ":sequence"
}
func acceptanceSeenKey(scope RecipientAcceptanceScope, messageID string) string {
	return acceptancePrefix(scope) + ":seen:" + acceptanceDigest(scope, messageID)
}
func acceptanceRecordKey(scope RecipientAcceptanceScope, messageID string) string {
	return acceptancePrefix(scope) + ":record:" + acceptanceDigest(scope, messageID)
}
func acceptanceDigest(scope RecipientAcceptanceScope, messageID string) string {
	sum := sha256.Sum256([]byte(scope.seenScope + "\x00" + messageID))
	return hex.EncodeToString(sum[:])
}
func redisValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return fmt.Sprint(v)
	}
}
