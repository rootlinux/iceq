package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestAnonymousLimiterRotationIncrementsBothAndOldBucketStillDenies(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	oldKey := "ratelimit:login:old"
	newKey := "ratelimit:login:new"
	mr.Set(oldKey, "5")
	mr.SetTTL(oldKey, time.Minute)
	count, err := redis.NewScript(rateLimitScript).Run(ctx, client, []string{newKey, oldKey}, 60).Int64()
	if err != nil {
		t.Fatal(err)
	}
	if count != 6 {
		t.Fatalf("maximum count = %d, want 6 from previous bucket", count)
	}
	if got, _ := mr.Get(newKey); got != "1" {
		t.Fatalf("current bucket = %q, want 1", got)
	}
	if got, _ := mr.Get(oldKey); got != "6" {
		t.Fatalf("previous bucket = %q, want 6", got)
	}
}
