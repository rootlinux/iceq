package hub

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestSendRejectsReservedAccountWipedBeforeRedisFanout(t *testing.T) {
	server := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	h := New(rdb)
	raw := []byte(`{"type":"account_wiped","id":"00000000-0000-4000-8000-000000000001","ts":1,"payload":{}}`)

	if err := h.Send(context.Background(), 10000001, raw); err != nil {
		t.Fatal(err)
	}
	if keys := server.Keys(); len(keys) != 0 {
		t.Fatalf("reserved control reached Redis: %v", keys)
	}
}
