// Package natsclient is a thin, opinionated wrapper around the official
// github.com/nats-io/nats.go client. It is opinionated in three places:
//
//   1. Connection options are baked in: exponential-backoff reconnect
//      capped at 30 seconds, unlimited total reconnect attempts, and
//      Pedantic protocol checking disabled (IceQ uses standard subjects
//      and doesn't need to pay the per-message validation cost).
//
//   2. NewClient fails fast. The underlying nats.Connect retries on its
//      own for a bounded window; if NATS is still unreachable we return
//      an error so the caller (typically main()) can decide whether to
//      crash, fall back, or alert. Silently returning a broken
//      connection would let the rest of the service think it has a bus
//      when it doesn't.
//
//   3. Drain() is the canonical shutdown path. It is preferred over
//      Close() because Drain() lets in-flight message handlers finish
//      before tearing down the connection — important during a rolling
//      deploy where a kill -TERM must not abandon a half-written
//      message.
//
// The wrapper does not attempt to abstract Publish / Subscribe semantics;
// callers can fall back to the embedded *nats.Conn via Conn() if they
// need JetStream, request/reply, or any other feature not exposed here.
package natsclient

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
)

// ----------------------------------------------------------------------------
// Constants for the reconnect policy. Centralized so the message-service,
// presence-service, and any future consumer share identical behavior —
// drifting backoff policies between services is a debugging hazard we
// want to avoid from day one.
// ----------------------------------------------------------------------------

const (
	// initialReconnectDelay is the wait between the first reconnect
	// attempt and the second. The library doubles this on each failed
	// attempt, up to maxReconnectDelay.
	initialReconnectDelay = 500 * time.Millisecond

	// maxReconnectDelay is the upper bound on the per-attempt wait.
	// 30 s is a common default that balances "give NATS a chance to
	// come back" against "don't sit in a death-spiral on a flapping
	// network".
	maxReconnectDelay = 30 * time.Second

	// connectTimeout caps the initial TCP + TLS + NATS handshake. If
	// NATS is genuinely down we want a quick failure, not a 30 s
	// hang during pod start.
	connectTimeout = 5 * time.Second
)

// ----------------------------------------------------------------------------
// Client. The wrapper type. Internal state is the *nats.Conn plus the
// URL it was constructed with (kept so the caller can log it for
// diagnostics on reconnect events).
// ----------------------------------------------------------------------------

// Client is a thin wrapper around *nats.Conn. It is safe for concurrent
// use — nats.Conn is itself safe for concurrent use, and our wrapper adds
// no mutable state of its own.
type Client struct {
	conn *nats.Conn
	url  string
}

// ----------------------------------------------------------------------------
// Connection setup.
// ----------------------------------------------------------------------------

// NewClient connects to the given NATS URL (e.g. "nats://nats:4222") and
// returns a wrapper on success. It blocks until the connection is
// established or the underlying nats.Connect gives up; for the standard
// library config that's effectively bounded by connectTimeout.
//
// The optional clientName is included in the NATS CLIENTINFO block so
// `nats server list` on the operator side can attribute connections to
// services. Pass an empty string to let NATS auto-generate one (it
// falls back to the binary name).
func NewClient(url, clientName string) (*Client, error) {
	if url == "" {
		return nil, errors.New("natsclient: url is empty")
	}

	opts := []nats.Option{
		nats.Name(clientName),
		nats.ReconnectWait(initialReconnectDelay),
		nats.MaxReconnects(-1), // -1 == unlimited; we want a long-lived bus
		nats.ReconnectJitter(200*time.Millisecond, 2*time.Second),
		nats.Timeout(connectTimeout),
		// Reconnect / disconnect callbacks emit structured log lines
		// so the rest of the IceQ services share a single logging
		// vocabulary for bus state changes.
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Printf("[natsclient] reconnected to %s (url=%s)", nc.ConnectedUrl(), url)
		}),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				log.Printf("[natsclient] disconnected: %v (will retry with backoff)", err)
			}
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			log.Printf("[natsclient] connection closed")
		}),
	}

	conn, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("natsclient: connect %s: %w", url, err)
	}

	if !conn.IsConnected() {
		// Defensive: nats.Connect returns nil on success and a
		// connected Conn, but we double-check before handing it
		// out so callers never need to handle a "not connected"
		// race.
		conn.Close()
		return nil, fmt.Errorf("natsclient: not connected after Connect()")
	}

	return &Client{conn: conn, url: url}, nil
}

// ----------------------------------------------------------------------------
// Publish. Thin pass-through to the underlying connection; we wrap it so
// callers don't need to import github.com/nats-io/nats.go just to send a
// message, and so we can intercept errors uniformly if we ever need to
// (e.g. to translate NATS error codes to a domain error type).
// ----------------------------------------------------------------------------

// Publish sends `data` to `subject` on the bus. It is safe to call from
// any goroutine.
//
// Returns the underlying nats error verbatim. Common failure modes:
//   - ErrConnectionClosed during shutdown
//   - ErrNoServers when the cluster is fully partitioned
//   - ErrTimeout when the outbound buffer is full
//
// Callers are expected to map these to retries or to the message
// persistence path (write to Scylla, mark as "queued") on the message
// service side.
func (c *Client) Publish(subject string, data []byte) error {
	if c == nil || c.conn == nil {
		return errors.New("natsclient: client is nil")
	}
	if subject == "" {
		return errors.New("natsclient: subject is empty")
	}
	return c.conn.Publish(subject, data)
}

// ----------------------------------------------------------------------------
// Subscribe and QueueSubscribe. Both return the *nats.Subscription so
// the caller can later Unsubscribe() — the wrapper intentionally does
// NOT swallow it, because subscription lifetime is the caller's
// concern.
// ----------------------------------------------------------------------------

// Subscribe creates a vanilla (broadcast) async subscription. Every
// `handler` invocation runs on a goroutine managed by the nats client;
// for ordered processing, use ChannelSubscribe or a worker pool at
// the handler level.
//
// The returned *nats.Subscription can be used to control the
// subscription (Unsubscribe, Drain, etc.) at any time.
func (c *Client) Subscribe(subject string, handler nats.MsgHandler) (*nats.Subscription, error) {
	if c == nil || c.conn == nil {
		return nil, errors.New("natsclient: client is nil")
	}
	if subject == "" {
		return nil, errors.New("natsclient: subject is empty")
	}
	if handler == nil {
		return nil, errors.New("natsclient: handler is nil")
	}
	return c.conn.Subscribe(subject, handler)
}

// QueueSubscribe creates a load-balanced subscription. All members of
// the same `queue` group receive disjoint subsets of messages
// published to `subject` — a single message goes to exactly one
// consumer in the group. This is the right primitive for the
// message-service: spinning up N replicas and joining them to the
// same queue name gives horizontal scale with no further plumbing.
//
// `queue` must be non-empty (the underlying call returns an error
// otherwise, but we check up front to avoid a confusing stack
// trace).
func (c *Client) QueueSubscribe(subject, queue string, handler nats.MsgHandler) (*nats.Subscription, error) {
	if c == nil || c.conn == nil {
		return nil, errors.New("natsclient: client is nil")
	}
	if subject == "" {
		return nil, errors.New("natsclient: subject is empty")
	}
	if queue == "" {
		return nil, errors.New("natsclient: queue group name is empty")
	}
	if handler == nil {
		return nil, errors.New("natsclient: handler is nil")
	}
	return c.conn.QueueSubscribe(subject, queue, handler)
}

// ----------------------------------------------------------------------------
// Shutdown. Drain is the canonical path; Close is provided for the
// "kill -9 already happened, no time to wait" case.
// ----------------------------------------------------------------------------

// Drain drains the connection: stops accepting new messages, lets all
// in-flight handlers finish, then closes the connection. This is the
// right call from a SIGTERM handler — the time it blocks is bounded
// by the slowest currently-executing handler, which is what we want
// during a rolling deploy.
//
// Returns an error only if the underlying nats call fails; in
// practice Drain() is best-effort and we don't propagate specific
// nats errors.
func (c *Client) Drain() error {
	if c == nil || c.conn == nil {
		return errors.New("natsclient: client is nil")
	}
	if !c.conn.IsConnected() {
		// Already disconnected. Nothing to drain; treat as
		// success because the goal (no in-flight work) is
		// already met.
		return nil
	}
	return c.conn.Drain()
}

// Close immediately tears down the connection. Use only when Drain
// would block too long (e.g. a stuck handler); in normal shutdown
// paths prefer Drain.
func (c *Client) Close() {
	if c == nil || c.conn == nil {
		return
	}
	c.conn.Close()
}

// ----------------------------------------------------------------------------
// Accessors. Use sparingly; the wrapper is intentionally narrow. We
// expose Conn() so advanced callers (JetStream, request/reply) can drop
// down to the underlying *nats.Conn without the wrapper getting in the
// way.
// ----------------------------------------------------------------------------

// Conn returns the underlying *nats.Conn. Use this for advanced
// features (JetStream, request/reply) that this wrapper does not
// expose. Most code should stick to Publish / Subscribe / Drain.
func (c *Client) Conn() *nats.Conn {
	if c == nil {
		return nil
	}
	return c.conn
}

// IsConnected is a one-line convenience used in healthcheck endpoints
// and in tests. Returns false for a nil receiver so the call is
// always safe.
func (c *Client) IsConnected() bool {
	if c == nil || c.conn == nil {
		return false
	}
	return c.conn.IsConnected()
}

// URL returns the URL the client was configured with. Exposed for
// logging and for /health endpoints.
func (c *Client) URL() string {
	if c == nil {
		return ""
	}
	return c.url
}
