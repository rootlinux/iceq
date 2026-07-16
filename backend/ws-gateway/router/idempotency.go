package router

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/iceq/iceq/ws-gateway/client"
	"github.com/redis/go-redis/v9"
)

const idempotencyTTL = 7 * 24 * time.Hour

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
	ok, err := d.rdb.SetNX(ctx, key, serverID, idempotencyTTL).Result()
	if err != nil {
		return "", false, err
	}
	if ok {
		return serverID, false, nil
	}
	prior, err := d.rdb.Get(ctx, key).Result()
	if err != nil {
		return "", false, err
	}
	return prior, true, nil
}
func (d *RedisMessageDeduper) Release(ctx context.Context, sender int64, clientID, serverID string) error {
	if clientID == "" {
		return nil
	}
	const script = `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end`
	return d.rdb.Eval(ctx, script, []string{idempotencyKey(sender, clientID)}, serverID).Err()
}
func idempotencyKey(sender int64, clientID string) string {
	sum := sha256.Sum256([]byte(clientID))
	return "send:idempotency:" + strconv.FormatInt(sender, 10) + ":" + hex.EncodeToString(sum[:])
}
