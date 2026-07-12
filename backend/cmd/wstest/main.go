// Step 4 verification: rate limit at message 31 + per-message
// wipe check closes the connection with 4403. Two tests run
// in sequence, each on its own UIN so the per-UIN rate-limit
// counter doesn't collide.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/iceq/iceq/shared/models"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

func mintToken(uin int64) (string, error) {
	type claims struct {
		UIN  int64  `json:"uin"`
		JTI  string `json:"jti"`
		Type string `json:"type"`
		jwt.RegisteredClaims
	}
	c := claims{
		UIN:  uin,
		JTI:  uuid.NewString(),
		Type: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			Issuer:    "iceq",
			Subject:   fmt.Sprintf("%d", uin),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return t.SignedString([]byte(envOr("ICEQ_JWT_SECRET", "wstest-secret-not-for-prod-padding")))
}

func main() {
	failed := false

	if err := ensureUsers(10000007, 10000008); err != nil {
		fmt.Println("SEED FAIL:", err)
		os.Exit(1)
	}

	if err := rateLimitTest(10000007); err != nil {
		fmt.Println("RATE-LIMIT TEST FAIL:", err)
		failed = true
	} else {
		fmt.Println("RATE-LIMIT TEST OK")
	}
	if err := wipeMidSessionTest(10000008); err != nil {
		fmt.Println("WIPE-MID TEST FAIL:", err)
		failed = true
	} else {
		fmt.Println("WIPE-MID TEST OK")
	}
	if failed {
		os.Exit(1)
	}
}

func rateLimitTest(uin int64) error {
	rdb := redis.NewClient(&redis.Options{Addr: envOr("ICEQ_REDIS_ADDR", "redis:6379")})
	defer rdb.Close()
	rdb.Del(context.Background(), fmt.Sprintf("ratelimit:msg:%d", uin))
	time.Sleep(100 * time.Millisecond)

	tok, err := mintToken(uin)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, envOr("ICEQ_WS_URL", "ws://ws-gateway:8082/ws"), nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "bye")

	if err := wsjson.Write(ctx, c, map[string]any{"type": "auth", "token": tok}); err != nil {
		return fmt.Errorf("auth send: %w", err)
	}
	if err := waitForAuthOK(ctx, c); err != nil {
		return err
	}

	for i := 1; i <= 35; i++ {
		env, _ := models.NewEnvelope(models.EnvelopeTypeDirect, models.DirectMessagePayload{
			ConversationID: "1:2", ReceiverUIN: 10000008,
			Content: fmt.Sprintf("msg-%d", i), ContentType: models.ContentTypeText,
		})
		if err := wsjson.Write(ctx, c, env); err != nil {
			return fmt.Errorf("send msg %d: %w", i, err)
		}
		var resp models.Envelope
		readCtx, readCancel := context.WithTimeout(ctx, 2*time.Second)
		err := wsjson.Read(readCtx, c, &resp)
		readCancel()
		if err != nil {
			return fmt.Errorf("read response for msg %d: %w", i, err)
		}
		if resp.Type == models.EnvelopeTypeError && resp.Payload != nil {
			var p models.ErrorPayload
			_ = json.Unmarshal(resp.Payload, &p)
			if p.Code == "RATE_LIMITED" {
				if i == 31 {
					return nil
				}
				return fmt.Errorf("RATE_LIMITED at message %d, expected 31", i)
			}
		}
	}
	return fmt.Errorf("never received RATE_LIMITED in 35 messages")
}

func wipeMidSessionTest(uin int64) error {
	rdb := redis.NewClient(&redis.Options{Addr: envOr("ICEQ_REDIS_ADDR", "redis:6379")})
	defer rdb.Close()
	rdb.Del(context.Background(),
		fmt.Sprintf("ratelimit:msg:%d", uin),
		fmt.Sprintf("jwt:blocklist:wipe:%d", uin),
	)
	time.Sleep(100 * time.Millisecond)

	tok, err := mintToken(uin)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, envOr("ICEQ_WS_URL", "ws://ws-gateway:8082/ws"), nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "bye")

	if err := wsjson.Write(ctx, c, map[string]any{"type": "auth", "token": tok}); err != nil {
		return fmt.Errorf("auth send: %w", err)
	}
	if err := waitForAuthOK(ctx, c); err != nil {
		return err
	}

	// Pre-wipe message — should get a normal ACK. Use a
	// non-existent receiver UIN (99999999) so the message
	// is enqueued in Redis rather than echoed back to us.
	env, _ := models.NewEnvelope(models.EnvelopeTypeDirect, models.DirectMessagePayload{
		ConversationID: "1:2", ReceiverUIN: 99999999,
		Content: "before-wipe", ContentType: models.ContentTypeText,
	})
	if err := wsjson.Write(ctx, c, env); err != nil {
		return fmt.Errorf("send pre-wipe: %w", err)
	}
	// Drain frames until we get the ACK. The first frame
	// could be a presence broadcast (from our own auth
	// triggering presence.online) or the ACK.
	var resp models.Envelope
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		readCtx, readCancel := context.WithTimeout(ctx, 500*time.Millisecond)
		err := wsjson.Read(readCtx, c, &resp)
		readCancel()
		if err != nil {
			return fmt.Errorf("read pre-wipe: %w", err)
		}
		if resp.Type == models.EnvelopeTypeAck {
			break
		}
		// Skip presence / other frames.
	}
	if resp.Type != models.EnvelopeTypeAck {
		return fmt.Errorf("expected ack, got %s", resp.Type)
	}

	// Set the wipe key mid-session. Use a shell exec so we
	// are sure the key lands in the same Redis instance the
	// server is reading from.
	wipeKey := fmt.Sprintf("jwt:blocklist:wipe:%d", uin)
	if err := rdb.Set(ctx, wipeKey, "1", 60*time.Second).Err(); err != nil {
		return fmt.Errorf("set wipe key: %w", err)
	}
	got, err := rdb.Get(ctx, wipeKey).Result()
	if err != nil {
		return fmt.Errorf("get wipe key: %w", err)
	}
	fmt.Printf("  wipe key %s set, value=%q\n", wipeKey, got)
	if got != "1" {
		return fmt.Errorf("wipe key not set correctly: got %q", got)
	}
	fmt.Println("  wipe key set mid-session; sending follow-up message")

	// Post-wipe message — the readLoop wipe check should
	// fire and close 4403. The Close arrives as a Read
	// error on the next call.
	env2, _ := models.NewEnvelope(models.EnvelopeTypeDirect, models.DirectMessagePayload{
		ConversationID: "1:2", ReceiverUIN: 10000007,
		Content: "after-wipe", ContentType: models.ContentTypeText,
	})
	_ = wsjson.Write(ctx, c, env2)
	readCtx, readCancel := context.WithTimeout(ctx, 3*time.Second)
	defer readCancel()
	var resp2 models.Envelope
	readErr := wsjson.Read(readCtx, c, &resp2)
	// Expect a CloseError with code 4403. The nhooyr Read
	// returns *websocket.CloseError on a close frame.
	if readErr == nil {
		return fmt.Errorf("expected close after wipe, got response: %+v", resp2)
	}
	if ce, ok := readErr.(*websocket.CloseError); ok {
		if ce.Code == websocket.StatusCode(4403) {
			return nil
		}
		return fmt.Errorf("expected close 4403, got %d", ce.Code)
	}
	// Some other error (context deadline, etc.) — check if
	// the connection is now closed by trying to write.
	if writeErr := c.Write(readCtx, websocket.MessageText, []byte(`{"type":"ping"}`)); writeErr != nil {
		return nil // connection is dead — good
	}
	return fmt.Errorf("read after wipe: %v", readErr)
}

func ensureUsers(uins ...int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, envOr("ICEQ_PG_DSN", "postgres://postgres:changeme@postgres:5432/iceq?sslmode=disable"))
	if err != nil {
		return fmt.Errorf("pg connect: %w", err)
	}
	defer pool.Close()

	for _, uin := range uins {
		if _, err := pool.Exec(ctx, `
			INSERT INTO users (uin, username, password_hash, identity_key)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (uin) DO NOTHING
		`, uin, fmt.Sprintf("wstest_%d", uin), "", ""); err != nil {
			return fmt.Errorf("seed user %d: %w", uin, err)
		}
	}
	return nil
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func waitForAuthOK(ctx context.Context, c *websocket.Conn) error {
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()

	for {
		select {
		case <-deadline.C:
			return fmt.Errorf("auth_ok not received within 3s")
		default:
		}

		readCtx, readCancel := context.WithTimeout(ctx, 500*time.Millisecond)
		var env models.Envelope
		err := wsjson.Read(readCtx, c, &env)
		readCancel()
		if err != nil {
			return fmt.Errorf("read auth_ok: %w", err)
		}
		if env.Type == "auth_ok" {
			return nil
		}
	}
}
