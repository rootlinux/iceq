package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ----------------------------------------------------------------------------
// Redis client. go-redis/v9 is the modern Redis client for Go; it
// returns a *redis.Client that internally manages a connection
// pool. We pin the pool size and a small dial timeout so the local
// stack has predictable startup behavior.
// ----------------------------------------------------------------------------

const (
	// redisPoolSize is the per-process connection count for
	// Redis. 10 is the go-redis default and is generous for
	// IceQ's footprint: presence lookups, undelivered-queue
	// pops, JWT blocklist checks, and rate-limit counters all
	// share the same pool and a single Redis instance can
	// comfortably service several hundred thousand ops/s on
	// modern hardware.
	redisPoolSize = 10

	// redisMinIdleConns is the floor on idle connections the
	// pool keeps ready. 2 means a cold pod has at most a
	// 2-connection cold-start penalty before requests have
	// to wait for a fresh dial.
	redisMinIdleConns = 2

	// redisDialTimeout caps the TCP dial for a new
	// connection. We do not want a dead Redis to keep the
	// service start hostage past 3 s.
	redisDialTimeout = 3 * time.Second

	// redisReadTimeout caps a single command read. The
	// default of 3 s is fine for a healthy Redis; we set it
	// explicitly so it is visible in code review.
	redisReadTimeout = 3 * time.Second

	// redisWriteTimeout caps a single command write. Same
	// rationale as ReadTimeout.
	redisWriteTimeout = 3 * time.Second

	// redisPingTimeout caps the initial PING that verifies
	// the connection. 3 s matches DialTimeout; if Redis is
	// up enough to dial, it is up enough to PING.
	redisPingTimeout = 3 * time.Second
)

// NewRedisClient builds and verifies a *redis.Client. It returns
// the client on success, or an error wrapping whatever the dial
// or ping step reported.
//
// The address is taken from cfg.RedisAddr or, if empty, the
// ICEQ_REDIS_ADDR environment variable (default "redis:6379").
// The password is taken from cfg.RedisPassword or
// ICEQ_REDIS_PASSWORD (default empty). The DB index is taken from
// cfg.RedisDB, falling back to ICEQ_REDIS_DB, defaulting to 0.
//
// The returned client owns its connection pool; the caller must
// call Close() during shutdown so the pool drains cleanly.
func NewRedisClient(cfg Config) (*redis.Client, error) {
	addr := cfg.RedisAddr
	if addr == "" {
		addr = envOr("ICEQ_REDIS_ADDR", "redis:6379")
	}
	password := cfg.RedisPassword
	if password == "" {
		password = envOr("ICEQ_REDIS_PASSWORD", "")
	}
	db := cfg.RedisDB
	if db == 0 {
		// Only consult the env var when the struct field is
		// zero. envIntOr falls back to 0 (== default) when
		// unset, which is what we want.
		db = envIntOr("ICEQ_REDIS_DB", 0)
	}

	if addr == "" {
		return nil, errors.New("db: RedisAddr is empty (set ICEQ_REDIS_ADDR or Config.RedisAddr)")
	}
	// Production deployments MUST authenticate every Redis connection.
	// When ICEQ_REDIS_REQUIRE_AUTH=1 the password must be non-empty or
	// the service refuses to start. Acceptance/development may omit this
	// guard and rely on the Redis server's NOAUTH rejection instead.
	if envOr("ICEQ_REDIS_REQUIRE_AUTH", "") == "1" && password == "" {
		return nil, errors.New("db: ICEQ_REDIS_PASSWORD is required when ICEQ_REDIS_REQUIRE_AUTH=1 (production Redis must be password-protected)")
	}
	if db < 0 {
		return nil, fmt.Errorf("db: RedisDB is negative: %d", db)
	}

	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           db,
		PoolSize:     redisPoolSize,
		MinIdleConns: redisMinIdleConns,
		DialTimeout:  redisDialTimeout,
		ReadTimeout:  redisReadTimeout,
		WriteTimeout: redisWriteTimeout,
	})

	// Active ping with a bounded deadline. We fail fast on a
	// missing Redis: the service cannot function without it
	// (presence, blocklist, undelivered queue all read
	// through this client), so starting in a half-broken
	// state would only defer the failure.
	pingCtx, cancel := context.WithTimeout(context.Background(), redisPingTimeout)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("db: ping redis at %s: %w", addr, err)
	}

	return client, nil
}
