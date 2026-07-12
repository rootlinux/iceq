package handlers

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPanicWipeRevokesSessionsBeforeScyllaCleanup(t *testing.T) {
	src, err := os.ReadFile("panicwipe.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	revoke := strings.Index(s, "deps.Redis.Set(ctx")
	cleanup := strings.Index(s, "cleanupScylla(ctx")
	if revoke < 0 || cleanup < 0 || revoke >= cleanup {
		t.Fatalf("session revocation must precede Scylla cleanup: revoke=%d cleanup=%d", revoke, cleanup)
	}
}

type contextRecordingStore struct {
	canceled []bool
	bounded  []bool
}

func (s *contextRecordingStore) DeleteUserMessages(ctx context.Context, _ int64) error {
	_, bounded := ctx.Deadline()
	s.canceled = append(s.canceled, ctx.Err() != nil)
	s.bounded = append(s.bounded, bounded)
	return nil
}
func (s *contextRecordingStore) DeleteUserGroupMessages(ctx context.Context, _ int64) error {
	_, bounded := ctx.Deadline()
	s.canceled = append(s.canceled, ctx.Err() != nil)
	s.bounded = append(s.bounded, bounded)
	return nil
}

func TestCleanupScyllaUsesIndependentBoundedContext(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	store := &contextRecordingStore{}
	cleanupScylla(parent, store, 42, time.Second)
	if len(store.canceled) != 2 {
		t.Fatalf("cleanup calls = %d, want 2", len(store.canceled))
	}
	for i := range store.canceled {
		if store.canceled[i] {
			t.Fatal("cleanup inherited cancellation")
		}
		if !store.bounded[i] {
			t.Fatal("cleanup context is not bounded")
		}
	}
}
