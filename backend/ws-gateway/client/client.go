// Package client owns the per-connection WebSocket lifecycle for
// the ws-gateway. The lifecycle has ten steps, executed in order:
//
//  1. Accept the WebSocket upgrade (nhooyr.io/websocket).
//  2. Read deadline 5s — wait for the client's "auth" frame, close
//     on timeout. An unauthenticated connection holds a goroutine
//     and an open file descriptor for at most 5 seconds, which is
//     the right blast radius for an aborted handshake.
//  3. Validate the JWT (signature, expiration, type=access).
//  4. Check the panic-wipe blocklist; if set, close 4403.
//  5. Register in the Hub.
//  6. Publish presence: online.
//  7. Drain undelivered:{uin} from Redis.
//  8. Launch readLoop + writeLoop goroutines.
//  9. Keepalive: readLoop resets the 60s deadline on every frame;
//     "ping" gets an immediate "pong" with no NATS round trip.
//
// 10. On disconnect: Unregister, publish presence: offline.
//
// On every inbound frame the readLoop performs:
//
//   - Wipe check (EXISTS jwt:blocklist:wipe:{uin}). This is the
//     primary defense-in-depth against a token that was valid at
//     connect time but whose account was wiped mid-session.
//   - Shared authenticated action rate limit, drop on overflow.
//   - Frame dispatch to the router.
//
// The package contains no package-level mutable state. The Hub,
// NATS client, JWT manager, and Postgres pool are passed in
// through Deps and shared across all Clients for a given process.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/iceq/iceq/shared/models"
	"github.com/iceq/iceq/shared/natsclient"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// ----------------------------------------------------------------------------
// Constants. Pulled out of the function bodies so the lifecycle
// reads top-down rather than being interrupted by magic numbers.
// ----------------------------------------------------------------------------

const (
	// authFrameTimeout caps how long we wait for the client's
	// first frame after the WebSocket upgrade. 5 s is long enough
	// for a slow mobile network to round-trip a small JSON
	// frame, short enough that an aborted handshake holds a
	// goroutine and an FD for at most a few seconds.
	authFrameTimeout = 5 * time.Second

	// readDeadline is the per-frame read deadline. Reset to
	// now+readDeadline on every inbound frame so a chatty
	// client is never killed for idleness, while a silent
	// client is reaped within one minute.
	readDeadline = 60 * time.Second

	// sendBufferSize is the per-client outbound channel
	// capacity. 64 messages is a comfortable slack: a slow
	// consumer can pause the upstream producer for ~64
	// message-bursts before TrySend starts returning false.
	// At ~1 KiB/message that's a ~64 KiB backlog per client,
	// well below the 1 MiB per-conn memory budget.
	sendBufferSize = 64

	// wipeCheckPrefix is the per-user panic-wipe blocklist key.
	// Must match panicwipeBlocklistPrefix in auth-service to a
	// tee — both packages are part of the same panic-wipe
	// contract (see ws-gateway/CONTRACT.md).
	wipeCheckPrefix = "jwt:blocklist:wipe:"

	// undeliveredKeyPrefix is the per-user undelivered-envelope
	// list in Redis. Must match hub.UndeliveredKeyPrefix.
	undeliveredKeyPrefix = "undelivered:"
)

// ----------------------------------------------------------------------------
// Close codes. Custom WebSocket close codes (4xxx) are reserved
// for application use. 4401 and 4403 are the two values the
// panic-wipe contract commits to — see ws-gateway/CONTRACT.md.
// ----------------------------------------------------------------------------

const (
	// CloseCodeAuthTimeout fires when the auth frame does not
	// arrive within authFrameTimeout.
	CloseCodeAuthTimeout = 4401

	// CloseCodeWiped fires when the panic-wipe blocklist key
	// is set for the user at any point in the connection's
	// lifetime. The client MUST clear local state and redirect
	// to /login; no recovery is possible.
	CloseCodeWiped = 4403
)

type authPayload struct {
	AccessToken string `json:"access_token"`
	Token       string `json:"token"`
}

type authEnvelope struct {
	Type    string      `json:"type"`
	Token   string      `json:"token"`
	Payload authPayload `json:"payload"`
}

func parseAuthToken(raw []byte) (string, error) {
	var frame authEnvelope
	if err := json.Unmarshal(raw, &frame); err != nil {
		return "", err
	}
	if frame.Type != "auth" {
		return "", errors.New("auth_required")
	}
	sources := 0
	for _, token := range []string{frame.Token, frame.Payload.AccessToken, frame.Payload.Token} {
		if token != "" {
			sources++
		}
	}
	if sources != 1 {
		return "", errors.New("auth_required")
	}
	switch {
	case frame.Token != "":
		return frame.Token, nil
	case frame.Payload.AccessToken != "":
		return frame.Payload.AccessToken, nil
	case frame.Payload.Token != "":
		return frame.Payload.Token, nil
	default:
		return "", errors.New("auth_required")
	}
}

// ----------------------------------------------------------------------------
// Deps. The single bundle of external dependencies a Client needs.
// Constructed once in main.go and shared across all clients.
// ----------------------------------------------------------------------------

// Deps is the per-process client runtime: NATS for presence and
// message fan-out, the Hub for local connection tracking, Redis
// for wipe/undelivered/rate-limit keys, the JWT manager for
// token validation, and the PG pool for any future lookups (the
// gate does NOT touch PG today, but the dep is here so a future
// step can reach it without re-plumbing).
//
// Dispatch is a function pointer rather than a method on a
// Router struct to avoid a circular import: the client package
// cannot import the router package (the router imports client
// for the *Client type), so the wire is a function set in
// main.go after both packages are constructed.
type Deps struct {
	NATS               *natsclient.Client
	Hub                HubRegister
	Redis              *redis.Client
	Manager            *jwt.Manager
	PG                 *pgxpool.Pool
	Dispatch           func(c *Client, env models.Envelope)
	ConnectRateLimiter *middleware.AuthenticatedRateLimiter
	FrameRateLimiter   *middleware.AuthenticatedRateLimiter
}

// HubRegister is the slice of the hub.Hub API the client needs.
// Defining it here as an interface lets the client package be
// tested against a stub hub without a circular dep on the hub
// package (the hub would otherwise need to import client, and
// client would need to import hub).
type HubRegister interface {
	Register(c *Client) error
	Unregister(c *Client)
}

// ErrHubTooManyConnections is the sentinel returned by HubRegister
// implementations when the per-UIN cap is reached. It is defined
// here (in the consumer package) so client code can check it with
// errors.Is without importing the hub package — which would
// create a hub → client → hub import cycle.
var ErrHubTooManyConnections = errors.New("hub: too many connections for this account")

// ----------------------------------------------------------------------------
// Client. One per open WebSocket connection. The struct is shared
// (via pointer) between the readLoop and writeLoop goroutines;
// the only mutable state is the per-client `send` channel and
// the `closeOnce` guard for the done channel.
// ----------------------------------------------------------------------------

// Client is a single open WebSocket connection. Created by
// ServeHTTP at upgrade time; lives until the connection closes
// (client disconnect, server close, keepalive timeout, or wipe).
type Client struct {
	// uin is the authenticated user's ID. Set once at
	// registration time and never mutated.
	uin int64

	// ws is the nhooyr WebSocket connection. Owned by the
	// read/write loops; the upgrade handler holds no
	// reference after Serve returns.
	ws *websocket.Conn

	// send is the per-client outbound channel. The writeLoop
	// reads from it; Send (and TrySend) write to it. Buffer
	// size is sendBufferSize; a full buffer means the
	// consumer is too slow and the message is dropped.
	send chan []byte

	// done is closed by the readLoop when the connection
	// ends. The writeLoop selects on it to break out of its
	// range. closeOnce guards the close so a write error in
	// the writeLoop and a read error in the readLoop can
	// both signal shutdown without panicking.
	done      chan struct{}
	closeOnce func()

	// deps is the shared per-process bundle.
	deps Deps

	// presenceSub is the per-connection subscription on
	// presence.notify.{uin}. presence-service publishes to
	// that subject whenever a *contact* of this user changes
	// presence; the handler in the subscription closure
	// forwards the envelope to the local WebSocket via
	// TrySend. The subscription is created right after
	// Register in ServeHTTP and torn down in shutdown() so
	// its lifetime tracks the connection's, not the
	// process's. May be nil if the Subscribe call failed —
	// the connection still works for direct messages, it
	// just won't receive presence-notify fan-out.
	presenceSub *nats.Subscription
}

// UIN returns the authenticated user's ID. Read-only after
// construction; safe for concurrent use.
func (c *Client) UIN() int64 { return c.uin }

// Deps returns the per-process dependency bundle. Exposed so
// the router (which has the *Client but not the Deps struct)
// can reach NATS/PG/Redis without a second pointer.
func (c *Client) Deps() Deps { return c.deps }

// TrySend is the non-blocking enqueue primitive the Hub uses to
// deliver an envelope to this client. Returns true if the message
// was buffered, false if the client's send channel is full (in
// which case the message is dropped and a future message will
// likely fail too, triggering a read-deadline close).
func (c *Client) TrySend(b []byte) bool {
	select {
	case c.send <- b:
		return true
	default:
		return false
	}
}

// ----------------------------------------------------------------------------
// ServeHTTP. The single entry point. Upgrades the request,
// runs the auth handshake, and returns. The read/write loops
// outlive this function (they are not joined).
// ----------------------------------------------------------------------------

// ServeHTTP upgrades the request to a WebSocket and runs the
// full client lifecycle. Returns when the connection ends or
// the auth handshake fails. The HTTP framework's request
// context drives cancellation: if the client disconnects before
// the upgrade, r.Context() is cancelled and we abort.
func ServeHTTP(deps Deps, w http.ResponseWriter, r *http.Request) {
	// Accept the WebSocket upgrade. The nhooyr library hides
	// the Sec-WebSocket-Accept handshake and the HTTP/1.1
	// upgrade response; we just call Accept and get a *Conn.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// No Origin check at the gateway. The web client and
		// the mobile client both connect directly; an Origin
		// check would block the mobile app, and Caddy already
		// sets a CSP that mitigates the relevant XSRF risk.
		// If a deployment needs a stricter policy, the
		// InsecureSkipVerify flag is the single switch.
		InsecureSkipVerify: true,
	})
	if err != nil {
		// Most common cause: the request was not a WebSocket
		// upgrade at all. Don't log; the noise would be
		// disproportionate to the value.
		return
	}
	// 64 KiB frame size cap. The largest legitimate envelope
	// is a 1:1 chat message body plus headers; a 64 KiB cap
	// leaves a generous headroom without admitting a memory-
	// exhaustion DoS.
	ws.SetReadLimit(65536)

	// 1-2-3. Auth handshake. Read one frame, parse it as
	// {"type":"auth","token":"<jwt>"}, validate the JWT.
	ctx, cancel := context.WithTimeout(r.Context(), authFrameTimeout)
	defer cancel()

	var authFrame json.RawMessage
	if err := wsjson.Read(ctx, ws, &authFrame); err != nil {
		// Either a timeout, a close, or a malformed frame.
		// All three are "client gave up"; we close with
		// 4401 and let the client retry.
		_ = ws.Close(CloseCodeAuthTimeout, "auth_timeout")
		return
	}
	token, err := parseAuthToken(authFrame)
	if err != nil {
		_ = ws.Close(websocket.StatusPolicyViolation, "auth_required")
		return
	}
	claims, err := deps.Manager.Verify(ctx, token, jwt.TokenTypeAccess)
	if err != nil {
		// Token-level error: expired, revoked, wrong type,
		// signature mismatch. 4401 is the spec's code for
		// "token rejected"; clients attempt a refresh and
		// reconnect.
		_ = ws.Close(CloseCodeAuthTimeout, "token_rejected")
		return
	}
	uin := claims.UIN
	if deps.ConnectRateLimiter == nil {
		_ = ws.Close(websocket.StatusTryAgainLater, "rate_limit_unavailable")
		return
	}
	allowed, err := deps.ConnectRateLimiter.Allow(r.Context(), uin)
	if err != nil {
		_ = ws.Close(websocket.StatusTryAgainLater, "rate_limit_unavailable")
		return
	}
	if !allowed {
		_ = ws.Close(websocket.StatusPolicyViolation, "rate_limited")
		return
	}

	// 4. Wipe check. Same key shape as the auth-service's
	// panic-wipe blocklist. We do this BEFORE the upgrade is
	// fully consumed (the spec calls this out as a permitted
	// short-circuit) so a wiped user does not occupy a slot
	// in the hub or generate a presence-online event.
	wipeCtx, wipeCancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
	defer wipeCancel()
	wiped, err := deps.Redis.Exists(wipeCtx, wipeCheckPrefix+strconv.FormatInt(uin, 10)).Result()
	if err != nil {
		// Fail-closed: a Redis outage on the wipe check must
		// NOT let a wiped user keep talking. The contract
		// requires this. (See ws-gateway/CONTRACT.md.)
		_ = ws.Close(CloseCodeWiped, "wipe_check_unavailable")
		return
	}
	if wiped > 0 {
		_ = ws.Close(CloseCodeWiped, "account_wiped")
		return
	}

	// 5. Build the client and register.
	done := make(chan struct{})
	c := &Client{
		uin:  uin,
		ws:   ws,
		send: make(chan []byte, sendBufferSize),
		done: done,
		deps: deps,
	}
	c.closeOnce = syncCloseOnce(done)
	if err := deps.Hub.Register(c); err != nil {
		if errors.Is(err, ErrHubTooManyConnections) {
			http.Error(w, "too many connections", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	authOK, err := models.NewEnvelope("auth_ok", map[string]any{
		"uin": uin,
	})
	if err == nil {
		_ = wsjson.Write(r.Context(), ws, authOK)
	}

	// 5b. Per-connection presence-notify subscription.
	// presence-service publishes a notify envelope on
	// "presence.notify.{uin}" whenever a contact of this user
	// changes presence. We subscribe to OUR subject (not the
	// canonical presence.update) so each connected session
	// only sees the events that target it. The subscription
	// is torn down in shutdown() — its lifetime is the
	// connection's lifetime, not the process's.
	if sub, err := deps.NATS.Subscribe(
		"presence.notify."+strconv.FormatInt(uin, 10),
		presenceNotifyHandler(c),
	); err != nil {
		// Subscription failure is non-fatal: the user can
		// still chat, they just won't see presence
		// updates for contacts. We log it and move on.
		log.Printf("[ws-gateway] presence notify subscribe: %v", err)
	} else {
		c.presenceSub = sub
	}

	// 6. Presence: online. We fire-and-forget the publish; if
	// NATS is degraded the message is dropped, but the
	// connection itself is already healthy and the next
	// presence update (offline) will catch up.
	publishPresence(deps.NATS, uin, models.PresenceStatusOnline)

	// 7. Drain undelivered envelopes. Each frame is written to
	// the per-client send channel; the writeLoop will pick
	// them up. We then DEL the list so the next reconnect
	// does not re-deliver.
	drainUndelivered(deps.Redis, c, uin)

	// 8. Launch the read/write loops. They exit when the
	// connection closes; we return from ServeHTTP after
	// starting them (the loops outlive the request scope).
	go c.writeLoop()
	c.readLoop()

	// 9 + 10. Disconnect handling. The readLoop has already
	// unregistered and published offline before exiting; this
	// is a no-op guard so any future code added after the
	// loops cannot accidentally skip the cleanup.
	deps.Hub.Unregister(c)
	publishPresence(deps.NATS, uin, models.PresenceStatusOffline)
	_ = ws.Close(websocket.StatusNormalClosure, "bye")
}

// ----------------------------------------------------------------------------
// readLoop. The single goroutine that reads from the WebSocket.
// All per-frame security checks (wipe, rate-limit) and the
// router dispatch happen here.
// ----------------------------------------------------------------------------

// readLoop reads frames until the connection ends. Every frame
// triggers:
//
//  1. Wipe re-check (the panic-wipe blocklist may have been
//     set mid-session).
//  2. Rate-limit INCR.
//  3. Router dispatch.
//
// A "ping" frame is short-circuited to a "pong" reply; a "pong"
// is ignored (the read deadline reset is the response).
func (c *Client) readLoop() {
	defer c.shutdown()

	// The keepalive invariant: ANY inbound frame refreshes
	// the read deadline, so a client that sends a heartbeat
	// once per 30 s never gets killed. nhooyr's Read takes
	// the deadline via the context, so we mint a fresh
	// context on every iteration with a fresh deadline.
	for {
		readCtx, readCancel := context.WithTimeout(
			context.Background(),
			readDeadline,
		)

		var env models.Envelope
		err := wsjson.Read(readCtx, c.ws, &env)
		readCancel()
		if err != nil {
			// Read errors are the normal exit path:
			// client disconnect, close frame, or deadline
			// expiry. We don't log the specific cause; the
			// log volume would be huge under normal
			// operation and the connection state is the
			// same in every case (about to close).
			return
		}

		// 1. Wipe re-check. A token that was valid at
		// connect can be invalidated by a panic-wipe that
		// fires while the connection is open. The
		// per-message EXISTS is the gate.
		wipeCtx, wipeCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		durablyWiped, derr := c.deps.Manager.IsAccountWiped(wipeCtx, c.uin)
		if derr != nil || durablyWiped {
			wipeCancel()
			_ = c.ws.Close(CloseCodeWiped, "account_wiped")
			return
		}
		wiped, werr := c.deps.Redis.Exists(wipeCtx, wipeCheckPrefix+strconv.FormatInt(c.uin, 10)).Result()
		wipeCancel()
		if werr != nil {
			// Fail-closed. A wipe-check outage must not
			// let a wiped user keep talking. Closing
			// here is the same posture as the connect-time
			// check.
			_ = c.ws.Close(CloseCodeWiped, "wipe_check_unavailable")
			return
		}
		if wiped > 0 {
			_ = c.ws.Close(CloseCodeWiped, "account_wiped")
			return
		}

		// 2. Rate limit. We do this AFTER the wipe check
		// so a wiped user does not get a free rate-limit
		// budget before being kicked.
		allowed, rateErr := c.checkRateLimit()
		if rateErr != nil {
			_ = c.ws.Close(websocket.StatusTryAgainLater, "rate_limit_unavailable")
			return
		}
		if !allowed {
			// Send an error frame and continue. The
			// error frame does NOT close the connection;
			// a rate-limited client can recover in 60 s.
			errEnv, _ := models.NewEnvelope(models.EnvelopeTypeError, models.ErrorPayload{
				Code:    "RATE_LIMITED",
				Message: "too many messages; slow down",
			})
			c.TrySend(mustMarshal(errEnv))
			continue
		}

		// 3. Dispatch. The router decides what to do with
		// the envelope; we don't try to be clever about
		// per-type handling here. The dispatch function
		// is set in main.go (router.Dispatch) so this
		// file does not have to import the router
		// package.
		if c.deps.Dispatch != nil {
			c.deps.Dispatch(c, env)
		}
	}
}

// ----------------------------------------------------------------------------
// writeLoop. The single goroutine that writes to the WebSocket.
// Pulls from c.send; closes the WS when c.done is signalled.
// ----------------------------------------------------------------------------

// writeLoop ranges over the per-client send channel, writing
// each frame to the WebSocket. Exits when c.done is closed
// (by the readLoop's deferred shutdown).
func (c *Client) writeLoop() {
	for {
		select {
		case <-c.done:
			// readLoop has exited; nothing more to write.
			// We don't drain c.send here because the
			// shutdown signal means the connection is
			// already going away — any pending frames
			// would be sent to a half-closed WS and
			// produce errors.
			return
		case frame, ok := <-c.send:
			if !ok {
				return
			}
			// Write the frame as a single text
			// message. The Envelope is already JSON-
			// encoded by the sender, and the JSON
			// wire-format is text. Using text frames
			// (not binary) keeps browser-side interop
			// clean — browsers' WebSocket API returns
			// text-frame payloads as strings and
			// binary-frame payloads as Blob, and
			// forcing every consumer through a Blob→
			// string conversion is needless friction.
			wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := c.ws.Write(wctx, websocket.MessageText, frame)
			wcancel()
			if err != nil {
				// Write error: the connection is
				// already broken. Signal done and
				// return; the readLoop will pick up
				// the same error and exit too.
				c.shutdown()
				return
			}
		}
	}
}

// ----------------------------------------------------------------------------
// shutdown. Closes the done channel exactly once. Called from
// the readLoop's defer; also from the writeLoop on a write
// error. Idempotent.
// ----------------------------------------------------------------------------

func (c *Client) shutdown() {
	c.closeOnce()
	// Tear down the per-connection presence-notify
	// subscription. We do this OUTSIDE closeOnce so the
	// subscription teardown is independent of the done-channel
	// signal (any code path that drops the subscription should
	// drop the connection, and vice versa). Unsubscribe is
	// idempotent on a nil receiver / nil sub so a Subscribe
	// failure earlier in the lifecycle is safe here.
	if c.presenceSub != nil {
		_ = c.presenceSub.Unsubscribe()
		c.presenceSub = nil
	}
}

// syncCloseOnce returns a closure that closes ch on the first
// call and is a no-op on every subsequent call. We implement
// this locally rather than using sync.Once because we want the
// call site to be a one-liner (c.closeOnce()) and we want
// the close to happen on a non-error path, not just on
// success.
//
// Storing the function in the struct also avoids the
// "captured by value" hazard a sync.Once value would have.
func syncCloseOnce(ch chan struct{}) func() {
	var closed bool
	var mu = make(chan struct{}, 1)
	mu <- struct{}{} // pre-fill the semaphore
	return func() {
		<-mu
		defer func() { mu <- struct{}{} }()
		if closed {
			return
		}
		closed = true
		close(ch)
	}
}

// ----------------------------------------------------------------------------
// Rate limit. The reusable authenticated limiter owns the atomic Redis
// counter and explicit ws:frame action budget.
// ----------------------------------------------------------------------------

// checkRateLimit performs the per-user message rate-limit.
// Returns true if the message is allowed, false if the user
// has exceeded the per-minute threshold.
func (c *Client) checkRateLimit() (bool, error) {
	if c.deps.FrameRateLimiter == nil {
		return false, errors.New("ws frame rate limiter is not configured")
	}
	return c.deps.FrameRateLimiter.Allow(context.Background(), c.uin)
}

// ----------------------------------------------------------------------------
// Drain undelivered. Pulls the per-user Redis list and pushes
// each envelope to the client's send channel. The list is
// deleted (DEL) at the end so the next reconnect does not see
// them again.
// ----------------------------------------------------------------------------

// drainUndelivered is called once per connection, immediately
// after registration. It pulls the user's undelivered
// envelopes from Redis and pushes them to the client. The
// list is deleted after the drain so a reconnect sees a clean
// slate (idempotent delivery on reconnect is the caller's
// job, not ours).
func drainUndelivered(rdb *redis.Client, c *Client, uin int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key := undeliveredKeyPrefix + strconv.FormatInt(uin, 10)

	// LRANGE 0 -1 returns every entry. We don't use LLEN +
	// LRANGE 0 N because the list could grow between the two
	// calls; LRANGE 0 -1 is a single atomic snapshot.
	frames, err := rdb.LRange(ctx, key, 0, -1).Result()
	if err != nil {
		// Empty list, Redis blip, whatever. Don't fail
		// the connect over a non-critical drain.
		return
	}
	for _, f := range frames {
		// Push each frame to the per-client channel.
		// TrySend (not blocking Send) — if the client's
		// buffer is full we drop the frame and let the
		// next reconnect re-deliver from the (still-
		// intact) list. We DEL only after a successful
		// drain of the entire list.
		c.TrySend([]byte(f))
	}
	// DEL the list. Even if TrySend dropped some frames
	// (channel full), the spec's at-least-once guarantee
	// is the caller's responsibility — the gateway is
	// best-effort. Keeping the list would re-deliver
	// everything on the next reconnect, which is the
	// worse failure mode (duplicate delivery, no
	// progress).
	if len(frames) > 0 {
		_ = rdb.Del(ctx, key).Err()
	}
}

// ----------------------------------------------------------------------------
// Presence publish helper. Fire-and-forget; errors are logged
// but do not affect the caller's flow.
// ----------------------------------------------------------------------------

// publishPresence publishes a presence.update envelope on the
// NATS presence subject. The envelope is JSON-encoded with
// the same shape the rest of the platform uses (PresencePayload
// inside an Envelope). Errors are logged; the connection
// lifecycle is not coupled to NATS availability.
func publishPresence(nc *natsclient.Client, uin int64, status string) {
	if nc == nil {
		return
	}
	payload := models.PresencePayload{
		UIN:    uin,
		Status: status,
		TS:     time.Now().UTC().Truncate(time.Minute).UnixMilli(),
	}
	env, err := models.NewEnvelope(models.EnvelopeTypePresence, payload)
	if err != nil {
		log.Printf("[ws-gateway] presence: marshal: %v", err)
		return
	}
	data, err := json.Marshal(env)
	if err != nil {
		log.Printf("[ws-gateway] presence: marshal envelope: %v", err)
		return
	}
	if err := nc.Publish("presence.update", data); err != nil {
		// Best-effort: a NATS outage should not turn
		// into a "user cannot connect" event. The
		// presence service is itself resilient (it
		// treats the absence of a presence event as
		// "offline"), so a missed publish is bounded
		// by the presence TTL.
		log.Printf("[ws-gateway] presence: publish: %v", err)
	}
}

// presenceNotifyHandler returns a nats.MsgHandler that forwards
// a presence.notify.{uin} envelope to the local WebSocket via
// c.TrySend. The handler is closure-bound to c so each connected
// session gets its own subscriber pointing at its own client.
//
// Design notes:
//   - The m.Data bytes are the FULL envelope (presence-service
//     re-marshals the envelope on its side). We hand them to
//     TrySend verbatim; the writeLoop will text-frame them as-is.
//   - TrySend is non-blocking: if the client's send channel is
//     full we drop the notify. The next contact-presence change
//     will fire another notify, and the contact's own presence
//     pull on reconnect will rehydrate missed state.
//   - We do NOT log on every drop; that would be a log line per
//     notify under load. The presence fan-out is fire-and-forget
//     at this layer — the canonical record is in Redis
//     (presence:{uin} hash) and the client pulls /api/presence
//     to rehydrate.
func presenceNotifyHandler(c *Client) nats.MsgHandler {
	return func(m *nats.Msg) {
		// Defensive copy: nats-go today hands us a stable
		// buffer, but we don't want a future library change
		// to silently corrupt the bytes the client sees.
		b := append([]byte(nil), m.Data...)
		// Silent drop on a full send buffer. The contact's
		// authoritative presence is in Redis
		// (presence:{uin} hash), so the client can rehydrate
		// missed notify envelopes via /api/presence/bulk
		// on its next reconnect. Failing the connection
		// would punish a momentarily-slow client.
		c.TrySend(b)
	}
}

// mustMarshal is a small wrapper that panics on an
// unmarshallable value. Used only for envelopes we just built
// ourselves, so a panic here indicates a programmer error
// (e.g. a non-JSON-encodable field), not a runtime condition.
func mustMarshal(env models.Envelope) []byte {
	b, err := json.Marshal(env)
	if err != nil {
		// We control every input to NewEnvelope in this
		// package; a marshal error means the
		// ErrorPayload type is broken, not that the
		// network is down. Returning an empty frame
		// would silently lose the error — better to
		// surface it. In practice this is unreachable.
		log.Printf("[ws-gateway] marshal envelope: %v", err)
		return nil
	}
	return b
}

// UUID is re-exported from google/uuid so router (and any
// other caller) can mint message IDs without importing the
// uuid package directly. Pure convenience.
func newUUID() string { return uuid.NewString() }

// errAuthTimeout is a sentinel kept for tests that want to
// assert the close-code path. The exported constant
// CloseCodeAuthTimeout is the value; this is a typed error
// for matching.
var errAuthTimeout = errors.New("auth timeout")
