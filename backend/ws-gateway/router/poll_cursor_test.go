package router

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestPollCursorIsSingleUseOwnerBoundUnguessableAndBounded(t *testing.T) {
	m := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: m.Addr()})
	store := NewRedisPollStore(rdb)
	ctx := context.Background()
	first, err := store.issueCursor(ctx, 7, "1-0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.consumeCursor(ctx, 8, first); !errors.Is(err, ErrInvalidPollCursor) {
		t.Fatalf("cross-user err=%v", err)
	}
	if _, err := store.consumeCursor(ctx, 7, "guessed"); !errors.Is(err, ErrInvalidPollCursor) {
		t.Fatalf("guess err=%v", err)
	}
	got, err := store.consumeCursor(ctx, 7, first)
	if err != nil || got != "1-0" {
		t.Fatalf("consume=%q err=%v", got, err)
	}
	if _, err := store.consumeCursor(ctx, 7, first); !errors.Is(err, ErrInvalidPollCursor) {
		t.Fatalf("replay err=%v", err)
	}
	for i := 0; i < MaxOutstandingPollCursors+3; i++ {
		if _, err := store.issueCursor(ctx, 7, "2-0"); err != nil {
			t.Fatal(err)
		}
	}
	if n := rdb.HLen(ctx, pollCursorHashKey(7)).Val(); n > MaxOutstandingPollCursors {
		t.Fatalf("outstanding=%d", n)
	}
}
