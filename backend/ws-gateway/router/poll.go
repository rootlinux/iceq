package router

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/redis/go-redis/v9"
)

const (
	DefaultPollBatch          = 20
	MaxPollBatch              = 50
	DefaultPollWait           = 20 * time.Second
	MaxPollWait               = 25 * time.Second
	pollStreamTTL             = 7 * 24 * time.Hour
	pollStreamMaxLen          = 1000
	MaxOutstandingPollCursors = 4
)

var ErrInvalidPollCursor = errors.New("invalid poll cursor")

type PollRequest struct {
	UIN    int64
	Cursor string
	Limit  int
	Wait   time.Duration
}

type PollResult struct {
	Cursor    string            `json:"cursor"`
	Envelopes []json.RawMessage `json:"envelopes"`
}

type PollStore interface {
	Poll(context.Context, PollRequest) (PollResult, error)
}

func NewPollHandler(store PollStore) http.Handler {
	if store == nil {
		panic("poll store is nil")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		limit := boundedInt(r.URL.Query().Get("limit"), DefaultPollBatch, MaxPollBatch)
		waitMS := boundedInt(r.URL.Query().Get("wait_ms"), int(DefaultPollWait/time.Millisecond), int(MaxPollWait/time.Millisecond))
		result, err := store.Poll(r.Context(), PollRequest{UIN: uin, Cursor: r.URL.Query().Get("cursor"), Limit: limit, Wait: time.Duration(waitMS) * time.Millisecond})
		if errors.Is(err, ErrInvalidPollCursor) {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, "poll unavailable", http.StatusServiceUnavailable)
			return
		}
		if result.Envelopes == nil {
			result.Envelopes = []json.RawMessage{}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(result)
	})
}

func boundedInt(raw string, fallback, max int) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	if n > max {
		return max
	}
	return n
}

type RedisPollStore struct{ rdb *redis.Client }

func NewRedisPollStore(rdb *redis.Client) *RedisPollStore {
	if rdb == nil {
		panic("poll redis is nil")
	}
	return &RedisPollStore{rdb: rdb}
}

func (s *RedisPollStore) Enqueue(ctx context.Context, uin int64, envelope []byte) error {
	if uin <= 0 || len(envelope) == 0 || !json.Valid(envelope) {
		return errors.New("invalid poll envelope")
	}
	key := pollStreamKey(uin)
	pipe := s.rdb.Pipeline()
	pipe.XAdd(ctx, &redis.XAddArgs{Stream: key, MaxLen: pollStreamMaxLen, Approx: true, Values: map[string]any{"envelope": envelope}})
	pipe.Expire(ctx, key, pollStreamTTL)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *RedisPollStore) Poll(ctx context.Context, req PollRequest) (PollResult, error) {
	lastID := "0-0"
	if req.Cursor != "" {
		value, err := s.rdb.HGet(ctx, pollCursorHashKey(req.UIN), req.Cursor).Result()
		if errors.Is(err, redis.Nil) {
			return PollResult{}, ErrInvalidPollCursor
		}
		if err != nil {
			return PollResult{}, err
		}
		lastID = value
	}
	streams, err := s.rdb.XRead(ctx, &redis.XReadArgs{Streams: []string{pollStreamKey(req.UIN), lastID}, Count: int64(req.Limit), Block: req.Wait}).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return PollResult{}, err
	}
	envelopes := make([]json.RawMessage, 0, req.Limit)
	for _, stream := range streams {
		for _, msg := range stream.Messages {
			raw, ok := msg.Values["envelope"].(string)
			if !ok || !json.Valid([]byte(raw)) {
				continue
			}
			envelopes = append(envelopes, json.RawMessage(raw))
			lastID = msg.ID
		}
	}
	var token string
	if req.Cursor == "" {
		token, err = s.issueCursor(ctx, req.UIN, lastID)
	} else {
		token, err = s.advanceCursor(ctx, req.UIN, req.Cursor, lastID)
	}
	if err != nil {
		return PollResult{}, err
	}
	return PollResult{Cursor: token, Envelopes: envelopes}, nil
}

func pollStreamKey(uin int64) string      { return "poll:stream:" + strconv.FormatInt(uin, 10) }
func pollCursorHashKey(uin int64) string  { return "poll:cursors:" + strconv.FormatInt(uin, 10) }
func pollCursorOrderKey(uin int64) string { return "poll:cursor-order:" + strconv.FormatInt(uin, 10) }

const issueCursorScript = `
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
redis.call('RPUSH', KEYS[2], ARGV[1])
while redis.call('LLEN', KEYS[2]) > tonumber(ARGV[3]) do
  local old = redis.call('LPOP', KEYS[2]); redis.call('HDEL', KEYS[1], old)
end
redis.call('PEXPIRE', KEYS[1], ARGV[4]); redis.call('PEXPIRE', KEYS[2], ARGV[4]); return 1`

func (s *RedisPollStore) issueCursor(ctx context.Context, uin int64, streamID string) (string, error) {
	token := uuid.NewString()
	err := s.rdb.Eval(ctx, issueCursorScript, []string{pollCursorHashKey(uin), pollCursorOrderKey(uin)}, token, streamID, MaxOutstandingPollCursors, pollStreamTTL.Milliseconds()).Err()
	return token, err
}
func (s *RedisPollStore) consumeCursor(ctx context.Context, uin int64, token string) (string, error) {
	const script = `local v=redis.call('HGET',KEYS[1],ARGV[1]); if not v then return false end; redis.call('HDEL',KEYS[1],ARGV[1]); redis.call('LREM',KEYS[2],1,ARGV[1]); return v`
	v, err := s.rdb.Eval(ctx, script, []string{pollCursorHashKey(uin), pollCursorOrderKey(uin)}, token).Text()
	if errors.Is(err, redis.Nil) {
		return "", ErrInvalidPollCursor
	}
	if err != nil {
		return "", err
	}
	return v, nil
}
func (s *RedisPollStore) advanceCursor(ctx context.Context, uin int64, oldToken, streamID string) (string, error) {
	// Atomically consume the predecessor and issue its bounded successor.
	newToken := uuid.NewString()
	const script = `
local v=redis.call('HGET',KEYS[1],ARGV[1]); if not v then return 0 end
redis.call('HDEL',KEYS[1],ARGV[1]); redis.call('LREM',KEYS[2],1,ARGV[1])
redis.call('HSET',KEYS[1],ARGV[2],ARGV[3]); redis.call('RPUSH',KEYS[2],ARGV[2])
while redis.call('LLEN',KEYS[2]) > tonumber(ARGV[4]) do local old=redis.call('LPOP',KEYS[2]);redis.call('HDEL',KEYS[1],old) end
redis.call('PEXPIRE',KEYS[1],ARGV[5]);redis.call('PEXPIRE',KEYS[2],ARGV[5]);return 1`
	n, err := s.rdb.Eval(ctx, script, []string{pollCursorHashKey(uin), pollCursorOrderKey(uin)}, oldToken, newToken, streamID, MaxOutstandingPollCursors, pollStreamTTL.Milliseconds()).Int()
	if err != nil {
		return "", err
	}
	if n != 1 {
		return "", ErrInvalidPollCursor
	}
	return newToken, nil
}
