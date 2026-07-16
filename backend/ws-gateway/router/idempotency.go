package router

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/iceq/iceq/ws-gateway/client"
	"github.com/redis/go-redis/v9"
)

const (
	// Idempotency records cover the longest selectable disappearing-message
	// duration. Clients must not automatically retry an "off" message after
	// this bounded delivery window.
	idempotencyTTL  = 30 * 24 * time.Hour
	pendingLeaseTTL = 5 * time.Second
	pendingPoll     = 20 * time.Millisecond
)

func reserveMessageID(ctx context.Context, d client.MessageDeduper, sender int64, clientID, serverID string) (string, bool, error) {
	if clientID == "" {
		return serverID, false, nil
	}
	if d == nil {
		return "", false, errors.New("message deduper is not configured")
	}
	return d.Reserve(ctx, sender, clientID, serverID)
}

type RedisMessageDeduper struct{ rdb *redis.Client }

func NewRedisMessageDeduper(rdb *redis.Client) *RedisMessageDeduper {
	if rdb == nil {
		panic("idempotency redis is nil")
	}
	return &RedisMessageDeduper{rdb: rdb}
}
func (d *RedisMessageDeduper) Reserve(ctx context.Context, sender int64, clientID, serverID string) (string, bool, error) {
	key := idempotencyKey(sender, clientID)
	for {
		ok, err := d.rdb.SetNX(ctx, key, "pending:"+serverID, pendingLeaseTTL).Result()
		if err != nil {
			return "", false, err
		}
		if ok {
			return serverID, false, nil
		}
		prior, err := d.rdb.Get(ctx, key).Result()
		if errors.Is(err, redis.Nil) {
			continue
		}
		if err != nil {
			return "", false, err
		}
		if strings.HasPrefix(prior, "committed:") {
			return strings.TrimPrefix(prior, "committed:"), true, nil
		}
		// A pending reservation is never acknowledged. Wait for its owner to
		// commit, release, or lose the short lease, then retry atomically.
		select {
		case <-ctx.Done():
			return "", false, ctx.Err()
		case <-time.After(pendingPoll):
		}
	}
}
func (d *RedisMessageDeduper) Commit(ctx context.Context, sender int64, clientID, serverID string) error {
	if clientID == "" {
		return nil
	}
	const script = `if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3]); return 1 else return 0 end`
	result, err := d.rdb.Eval(ctx, script, []string{idempotencyKey(sender, clientID)}, "pending:"+serverID, "committed:"+serverID, idempotencyTTL.Milliseconds()).Int()
	if err != nil {
		return err
	}
	if result != 1 {
		return errors.New("idempotency lease ownership lost")
	}
	return nil
}
func (d *RedisMessageDeduper) Release(ctx context.Context, sender int64, clientID, serverID string) error {
	if clientID == "" {
		return nil
	}
	const script = `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end`
	return d.rdb.Eval(ctx, script, []string{idempotencyKey(sender, clientID)}, "pending:"+serverID).Err()
}
func idempotencyKey(sender int64, clientID string) string {
	sum := sha256.Sum256([]byte(clientID))
	return "send:idempotency:" + strconv.FormatInt(sender, 10) + ":" + hex.EncodeToString(sum[:])
}
