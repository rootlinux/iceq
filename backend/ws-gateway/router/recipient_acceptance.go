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
	ErrInvalidAcceptance = errors.New("invalid recipient acceptance")
	ErrAcceptanceExpired = errors.New("recipient acceptance expired")
)

// RecipientAcceptanceScope identifies one independently deduplicated recipient.
// Group messages include the group in the seen scope while still sharing the
// recipient's poll stream with direct messages.
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
	return RecipientAcceptanceScope{
		recipientUIN: recipientUIN,
		seenScope:    "group:" + hex.EncodeToString(sum[:16]),
	}, nil
}

// AcceptanceQueueKey is the common per-recipient stream consumed by the poll
// and WebSocket delivery paths.
func AcceptanceQueueKey(scope RecipientAcceptanceScope) string {
	return "poll:stream:" + strconv.FormatInt(scope.recipientUIN, 10)
}

type RecipientAcceptance struct {
	Scope     RecipientAcceptanceScope
	MessageID string
	Envelope  []byte
	// ExpiresAt nil means retention is off and both the seen marker and the
	// recipient stream remain TTL-less.
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
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 0
end

local stream_existed = redis.call('EXISTS', KEYS[2])
redis.call('XADD', KEYS[2], '*', 'message_id', ARGV[1], 'envelope', ARGV[2], 'scope', ARGV[3])

if ARGV[4] == 'off' then
  redis.call('SET', KEYS[1], '1')
  redis.call('PERSIST', KEYS[2])
else
  local ttl = tonumber(ARGV[5])
  redis.call('SET', KEYS[1], '1', 'PX', ttl)
  if stream_existed == 0 then
    redis.call('PEXPIRE', KEYS[2], ttl)
  else
    local current = redis.call('PTTL', KEYS[2])
    if current >= 0 and current < ttl then
      redis.call('PEXPIRE', KEYS[2], ttl)
    end
  end
end
return 1
`)

// Accept atomically records the scope/message seen marker and appends exactly
// one item to the recipient stream. A false result is a successful replay no-op.
func (s *RecipientAcceptanceStore) Accept(ctx context.Context, acceptance RecipientAcceptance) (bool, error) {
	if acceptance.Scope.recipientUIN <= 0 || acceptance.Scope.seenScope == "" ||
		strings.TrimSpace(acceptance.MessageID) == "" || len(acceptance.Envelope) == 0 {
		return false, ErrInvalidAcceptance
	}

	mode := "off"
	ttlMillis := int64(0)
	if acceptance.ExpiresAt != nil {
		remaining := acceptance.ExpiresAt.Sub(s.now())
		if remaining <= 0 {
			return false, ErrAcceptanceExpired
		}
		// Redis PX rejects zero. Round up so a positive sub-millisecond
		// remainder cannot accidentally become an invalid/expired TTL.
		ttlMillis = (remaining.Nanoseconds() + int64(time.Millisecond) - 1) / int64(time.Millisecond)
		mode = "expires"
	}

	seenKey := acceptanceSeenKey(acceptance.Scope, acceptance.MessageID)
	result, err := acceptRecipientScript.Run(ctx, s.rdb,
		[]string{seenKey, AcceptanceQueueKey(acceptance.Scope)},
		acceptance.MessageID, acceptance.Envelope, acceptance.Scope.seenScope, mode, ttlMillis,
	).Int64()
	if err != nil {
		return false, err
	}
	return result == 1, nil
}

// ReadAccepted exposes the stream in the representation needed by poll/WS
// delivery without removing entries or weakening replay protection.
func (s *RecipientAcceptanceStore) ReadAccepted(ctx context.Context, scope RecipientAcceptanceScope, start, stop string, count int64) ([]AcceptedEnvelope, error) {
	if scope.recipientUIN <= 0 || scope.seenScope == "" {
		return nil, ErrInvalidAcceptance
	}
	if start == "" {
		start = "-"
	}
	if stop == "" {
		stop = "+"
	}
	var (
		messages []redis.XMessage
		err      error
	)
	if count > 0 {
		messages, err = s.rdb.XRangeN(ctx, AcceptanceQueueKey(scope), start, stop, count).Result()
	} else {
		messages, err = s.rdb.XRange(ctx, AcceptanceQueueKey(scope), start, stop).Result()
	}
	if err != nil {
		return nil, err
	}
	out := make([]AcceptedEnvelope, 0, len(messages))
	for _, message := range messages {
		out = append(out, AcceptedEnvelope{
			StreamID:  message.ID,
			MessageID: streamString(message.Values["message_id"]),
			Envelope:  []byte(streamString(message.Values["envelope"])),
			Scope:     streamString(message.Values["scope"]),
		})
	}
	return out, nil
}

func acceptanceSeenKey(scope RecipientAcceptanceScope, messageID string) string {
	sum := sha256.Sum256([]byte(messageID))
	return "poll:seen:" + strconv.FormatInt(scope.recipientUIN, 10) + ":" + scope.seenScope + ":" + hex.EncodeToString(sum[:])
}

func streamString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return fmt.Sprint(typed)
	}
}
