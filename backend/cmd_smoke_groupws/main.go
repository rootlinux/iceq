package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/iceq/iceq/shared/models"
	"github.com/jackc/pgx/v5/pgxpool"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

const (
	aliceUIN int64 = 91000001
	bobUIN   int64 = 91000002
)

func main() {
	if err := run(); err != nil {
		fmt.Println("GROUP WS SMOKE FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("GROUP WS SMOKE OK: both group members received the group_msg via WS")
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := ensureUsers(ctx, aliceUIN, bobUIN); err != nil {
		return err
	}

	aliceToken, err := mintToken(aliceUIN)
	if err != nil {
		return fmt.Errorf("mint alice token: %w", err)
	}
	bobToken, err := mintToken(bobUIN)
	if err != nil {
		return fmt.Errorf("mint bob token: %w", err)
	}

	apiBase := strings.TrimRight(envOr("ICEQ_SMOKE_API_BASE", "http://caddy"), "/")
	wsURL := envOr("ICEQ_SMOKE_WS_URL", "ws://caddy/ws")

	groupID, err := createGroup(ctx, apiBase, aliceToken)
	if err != nil {
		return err
	}
	if err := addMember(ctx, apiBase, aliceToken, groupID, bobUIN); err != nil {
		return err
	}

	aliceWS, err := connectWS(ctx, wsURL, aliceToken)
	if err != nil {
		return fmt.Errorf("connect alice ws: %w", err)
	}
	defer aliceWS.Close(websocket.StatusNormalClosure, "done")
	bobWS, err := connectWS(ctx, wsURL, bobToken)
	if err != nil {
		return fmt.Errorf("connect bob ws: %w", err)
	}
	defer bobWS.Close(websocket.StatusNormalClosure, "done")

	text := "group smoke " + uuid.NewString()
	env, _ := models.NewEnvelope(models.EnvelopeTypeGroup, models.GroupMessagePayload{
		GroupID:     groupID,
		SenderUIN:   aliceUIN,
		Content:     text,
		ContentType: models.ContentTypeText,
		ClientID:    uuid.NewString(),
	})
	if err := wsjson.Write(ctx, aliceWS, env); err != nil {
		return fmt.Errorf("send group_msg: %w", err)
	}

	if err := waitForGroupMessage(ctx, aliceWS, groupID, text); err != nil {
		return fmt.Errorf("alice receive group_msg: %w", err)
	}
	if err := waitForGroupMessage(ctx, bobWS, groupID, text); err != nil {
		return fmt.Errorf("bob receive group_msg: %w", err)
	}
	return nil
}

func ensureUsers(ctx context.Context, uins ...int64) error {
	pool, err := pgxpool.New(ctx, postgresDSN())
	if err != nil {
		return fmt.Errorf("pg connect: %w", err)
	}
	defer pool.Close()

	for _, uin := range uins {
		if _, err := pool.Exec(ctx, `
			INSERT INTO users (uin, username, password_hash, identity_key)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (uin) DO UPDATE SET username = EXCLUDED.username
		`, uin, fmt.Sprintf("groupws_%d", uin), "", ""); err != nil {
			return fmt.Errorf("seed user %d: %w", uin, err)
		}
	}
	return nil
}

func postgresDSN() string {
	if v := strings.TrimSpace(os.Getenv("ICEQ_PG_DSN")); v != "" {
		return v
	}
	user := envOr("POSTGRES_USER", "postgres")
	password := envOr("POSTGRES_PASSWORD", "changeme")
	db := envOr("POSTGRES_DB", "iceq")
	return fmt.Sprintf("postgres://%s:%s@postgres:5432/%s?sslmode=disable", user, password, db)
}

func createGroup(ctx context.Context, apiBase, token string) (string, error) {
	var resp struct {
		GroupID string `json:"group_id"`
	}
	if err := doJSON(ctx, http.MethodPost, apiBase+"/api/groups/", token, map[string]string{
		"name": "Group smoke " + time.Now().UTC().Format("150405"),
	}, &resp); err != nil {
		return "", fmt.Errorf("create group: %w", err)
	}
	if resp.GroupID == "" {
		return "", fmt.Errorf("create group returned empty group_id")
	}
	return resp.GroupID, nil
}

func addMember(ctx context.Context, apiBase, token, groupID string, uin int64) error {
	if err := doJSON(ctx, http.MethodPost, apiBase+"/api/groups/"+groupID+"/members", token, map[string]int64{
		"uin": uin,
	}, nil); err != nil {
		return fmt.Errorf("add group member: %w", err)
	}
	return nil
}

func doJSON(ctx context.Context, method, url, token string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	resBody, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", res.Status, strings.TrimSpace(string(resBody)))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(resBody, out); err != nil {
		return err
	}
	return nil
}

func connectWS(ctx context.Context, wsURL, token string) (*websocket.Conn, error) {
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return nil, err
	}
	if err := wsjson.Write(ctx, c, map[string]any{"type": "auth", "token": token}); err != nil {
		c.Close(websocket.StatusInternalError, "auth send failed")
		return nil, err
	}
	if err := waitForAuthOK(ctx, c); err != nil {
		c.Close(websocket.StatusInternalError, "auth failed")
		return nil, err
	}
	return c, nil
}

func waitForAuthOK(ctx context.Context, c *websocket.Conn) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var env models.Envelope
		readCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
		err := wsjson.Read(readCtx, c, &env)
		cancel()
		if err != nil {
			continue
		}
		if env.Type == "auth_ok" {
			return nil
		}
		if env.Type == models.EnvelopeTypeError {
			return fmt.Errorf("error frame during auth: %s", string(env.Payload))
		}
	}
	return fmt.Errorf("timed out waiting for auth_ok")
}

func waitForGroupMessage(ctx context.Context, c *websocket.Conn, groupID, text string) error {
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		var env models.Envelope
		readCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
		err := wsjson.Read(readCtx, c, &env)
		cancel()
		if err != nil {
			continue
		}
		if env.Type != models.EnvelopeTypeGroup {
			continue
		}
		var payload models.GroupMessagePayload
		if err := json.Unmarshal(env.Payload, &payload); err != nil {
			return err
		}
		if payload.GroupID == groupID && payload.Content == text {
			return nil
		}
	}
	return fmt.Errorf("timed out waiting for group_msg")
}

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

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
