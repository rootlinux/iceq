// Package db provides connection factories for the three storage
// backends IceQ uses (Postgres, Scylla, Redis) plus a shared Config
// type. Each factory reads its connection target from a struct field
// AND an environment variable; the explicit struct field is the
// test-friendly path, the env var is the production-friendly path.
//
// All three factories are intentionally small: they parse config,
// build the underlying client with the agreed pool parameters, and
// verify the connection with a single ping. There is no retry loop
// or background health check here — those belong in the service's
// main(), where they can be paired with logging and metrics.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ----------------------------------------------------------------------------
// Config. The single configuration struct that flows into every
// factory. Fields can be populated by hand (test path) or by the
// helper constructors below (production path).
// ----------------------------------------------------------------------------

// Config carries the connection parameters for every storage
// backend. Zero value is NOT usable — every field has a
// corresponding env-var helper that fills in a sane default.
type Config struct {
	// PostgresDSN is a libpq-style DSN, e.g.
	//   "postgres://user:pass@host:5432/dbname?sslmode=disable"
	// For the local stack, ICEQ_PG_DSN defaults to
	//   "postgres://postgres:postgres@postgres:5432/iceq?sslmode=disable"
	PostgresDSN string

	// ScyllaHosts is a comma-separated list of host:port pairs,
	// e.g. "scylla:9042". For the local stack there is a single
	// node.
	ScyllaHosts string

	// ScyllaKeyspace is the keyspace to bind on connect. Required
	// because every query is qualified against it.
	ScyllaKeyspace string

	// RedisAddr is host:port, e.g. "redis:6379".
	RedisAddr string

	// RedisPassword is optional. Empty string means no auth.
	RedisPassword string

	// RedisDB is the logical database index (0..15 by default).
	// Defaults to 0; the IceQ stack uses 0 for everything.
	RedisDB int
}

// ----------------------------------------------------------------------------
// Postgres pool. pgx/v5 is the modern driver; pgxpool provides the
// connection pool. The IceQ services all use a single shared pool
// per process because pgxpool's connection reuse is most efficient
// when every goroutine borrows from the same backing set.
// ----------------------------------------------------------------------------

const (
	// pgMaxConns is the upper bound on open Postgres connections
	// per process. 25 was chosen as a sweet spot for a single
	// backend service: small enough to fit on a 2-core
	// container, large enough to absorb a burst of concurrent
	// REST handlers without queuing.
	pgMaxConns = 25

	// pgMinConns keeps a warm pool baseline so the first request
	// of a cold pod doesn't pay a TCP+TLS+startup tax. 5 is the
	// documented pgxpool starting point.
	pgMinConns = 5

	// pgMaxConnLifetime caps how long a single connection can
	// remain in the pool before being recycled. 1 hour is the
	// common production value: long enough to amortize
	// connection setup, short enough to dodge most cloud load
	// balancer idle timeouts.
	pgMaxConnLifetime = time.Hour

	// pgHealthCheckPeriod is how often the pool runs its
	// background health probe on idle connections. The default
	// (1 minute) is fine for our workload; we leave it
	// untouched to avoid surprises.
	pgHealthCheckPeriod = time.Minute

	// pgConnectTimeout caps the initial TCP+TLS+startup wait
	// for a single connection attempt. We do NOT want a slow
	// Postgres to hold the entire service start hostage.
	pgConnectTimeout = 5 * time.Second
)

// PostgresPoolConfig is the public form of pgxpool config returned to
// callers. We expose it (rather than the raw *pgxpool.Config) so the
// service layer can tweak pool parameters per-environment without
// importing pgx.
type PostgresPoolConfig struct {
	DSN             string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
}

// NewPostgresPool builds and pings a pgxpool. It returns the pool
// on success, or an error wrapping whatever the parse or ping
// step reported. The caller owns the pool and must call Close() on
// shutdown.
//
// If cfg.PostgresDSN is empty, the env-var fallback
// ICEQ_PG_DSN is consulted. We refuse to construct a pool with an
// empty DSN because that would default to a localhost socket path
// that is wrong in a container.
//
// The pool is verified with a Ping under a 5-second deadline. We
// do NOT retry on ping failure — the caller decides whether to
// crash, fall back, or alert.
func NewPostgresPool(cfg Config) (*pgxpool.Pool, error) {
	dsn := cfg.PostgresDSN
	if dsn == "" {
		// Lazy import of os is avoided by relying on the
		// Config helper (envOr) — keeping this package
		// independent of the os package for unit tests
		// that build a Config struct directly.
		dsn = envOr("ICEQ_PG_DSN", "")
	}
	if dsn == "" {
		return nil, errors.New("db: PostgresDSN is empty (set ICEQ_PG_DSN or Config.PostgresDSN)")
	}

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parse postgres DSN: %w", err)
	}

	// Override the connection-pool parameters. ParseConfig
	// filled in DSN-derived defaults (host, port, user, dbname,
	// sslmode); we override only the pool sizing here so the
	// production deployment can change MaxConns without
	// rewriting the DSN.
	poolCfg.MaxConns = pgMaxConns
	poolCfg.MinConns = pgMinConns
	poolCfg.MaxConnLifetime = pgMaxConnLifetime
	poolCfg.HealthCheckPeriod = pgHealthCheckPeriod

	// Build the pool. NewWithConfig dials lazily — the first
	// connection is opened on first use, not here. We
	// deliberately do not pre-fill the pool to avoid a slow
	// startup if Postgres is still warming.
	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		return nil, fmt.Errorf("db: new pgxpool: %w", err)
	}

	// Active ping with a bounded deadline. If Postgres is
	// unreachable at startup, fail fast so the orchestrator
	// can restart us.
	pingCtx, cancel := context.WithTimeout(context.Background(), pgConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping postgres: %w", err)
	}

	return pool, nil
}
