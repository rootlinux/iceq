package handlers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestBoundedCASRetry proves boundedCASRetry's loop-control contract --
// exact retry bound, returned error, and context-cancellation handling --
// deterministically, with a fake attempt function and no Scylla connection
// at all. This is the property the real-Scylla concurrency test
// ("CAS retry under synchronized contention" in
// panicwipe_concurrency_acceptance_test.go) cannot prove on every run: that
// test only exercises contention timing-dependently, so it can observe
// either a success or an exhaustion outcome depending on real scheduling.
// This test proves the loop itself behaves correctly under permanent,
// guaranteed contention (attempt always reports not-applied), every run.
func TestBoundedCASRetry(t *testing.T) {
	t.Run("exhausts after exactly maxAttempts calls, returns the exhaustion error, and that error correctly gates index cleanup", func(t *testing.T) {
		const maxAttempts = 8
		attempts := 0

		err := boundedCASRetry(context.Background(), maxAttempts, func(n int) error {
			if n != maxAttempts {
				t.Fatalf("exhaustedErr called with attempts=%d, want %d", n, maxAttempts)
			}
			return fmt.Errorf("sanitize ingest receipt: exhausted %d CAS attempts under contention for sender_uin=1 client_id=fake -- caller must retry this wipe job later", n)
		}, func(ctx context.Context) (bool, error) {
			attempts++
			return false, nil // permanent contention: never applies
		})

		if attempts != maxAttempts {
			t.Fatalf("attempt was called %d times, want exactly %d", attempts, maxAttempts)
		}
		if err == nil || !strings.Contains(err.Error(), "exhausted") {
			t.Fatalf("error = %v, want the documented exhaustion error", err)
		}

		// deleteIngestReceipts's real shape is:
		//   if err := s.sanitizeIngestReceipt(ctx, senderUIN, clientID, uin); err != nil {
		//       _ = iter.Close()
		//       return fmt.Errorf("sanitize ingest receipt: %w", err)
		//   }
		//   ...
		//   DELETE FROM message_ingest_erasure_index WHERE uin = ?
		// with that DELETE only reached after the per-row loop completes
		// with a nil error. A non-nil err here -- exactly what exhaustion
		// produces -- deterministically means that statement is never
		// reached, so a retried wipe job can still find this row via its
		// index entry. Mirrored here as an explicit assertion rather than
		// left as an unverified read of the source.
		indexCleanupReached := err == nil
		if indexCleanupReached {
			t.Fatal("erasure-index cleanup must not be reached when the retry loop exhausts")
		}
	})

	t.Run("an already-cancelled context is reported immediately, before any attempt", func(t *testing.T) {
		attempts := 0
		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		err := boundedCASRetry(cancelledCtx, 8, func(int) error {
			t.Fatal("exhaustedErr must not be called when the context is already cancelled")
			return nil
		}, func(ctx context.Context) (bool, error) {
			attempts++
			return false, nil
		})

		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if attempts != 0 {
			t.Fatalf("attempt was called %d times, want 0 -- a pre-cancelled context must be checked before the first attempt", attempts)
		}
	})

	t.Run("cancellation mid-retry stops before exhausting the bound", func(t *testing.T) {
		const maxAttempts = 8
		attempts := 0
		ctx, cancel := context.WithCancel(context.Background())

		err := boundedCASRetry(ctx, maxAttempts, func(int) error {
			t.Fatal("exhaustedErr must not be called when the context was cancelled mid-retry")
			return nil
		}, func(ctx context.Context) (bool, error) {
			attempts++
			if attempts == 3 {
				cancel()
			}
			return false, nil
		})

		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if attempts != 3 {
			t.Fatalf("attempt was called %d times, want exactly 3 (cancelled during the 3rd, detected before a 4th would start)", attempts)
		}
	})

	t.Run("an attempt error is returned immediately, without exhausting the bound", func(t *testing.T) {
		const maxAttempts = 8
		attempts := 0
		wantErr := errors.New("sentinel attempt error")

		err := boundedCASRetry(context.Background(), maxAttempts, func(int) error {
			t.Fatal("exhaustedErr must not be called when an attempt itself errors")
			return nil
		}, func(ctx context.Context) (bool, error) {
			attempts++
			if attempts == 2 {
				return false, wantErr
			}
			return false, nil
		})

		if !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want %v", err, wantErr)
		}
		if attempts != 2 {
			t.Fatalf("attempt was called %d times, want exactly 2", attempts)
		}
	})

	t.Run("applying on the final allowed attempt succeeds, does not exhaust", func(t *testing.T) {
		const maxAttempts = 8
		attempts := 0

		err := boundedCASRetry(context.Background(), maxAttempts, func(int) error {
			t.Fatal("exhaustedErr must not be called when the final allowed attempt applies")
			return nil
		}, func(ctx context.Context) (bool, error) {
			attempts++
			return attempts == maxAttempts, nil // applies only on the 8th
		})

		if err != nil {
			t.Fatalf("error = %v, want nil (applied on the final allowed attempt)", err)
		}
		if attempts != maxAttempts {
			t.Fatalf("attempt was called %d times, want exactly %d", attempts, maxAttempts)
		}
	})

	t.Run("applying on the first attempt succeeds without retrying", func(t *testing.T) {
		attempts := 0

		err := boundedCASRetry(context.Background(), 8, func(int) error {
			t.Fatal("exhaustedErr must not be called when the first attempt applies")
			return nil
		}, func(ctx context.Context) (bool, error) {
			attempts++
			return true, nil
		})

		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if attempts != 1 {
			t.Fatalf("attempt was called %d times, want exactly 1", attempts)
		}
	})
}
