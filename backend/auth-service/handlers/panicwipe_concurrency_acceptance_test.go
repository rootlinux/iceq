//go:build integration
// +build integration

// Package handlers -- real-Scylla concurrency tests for Task #13, proving
// the fix for a TOCTOU lost-update race in group-recipient list
// sanitization.
//
// Two wipe workers processing DIFFERENT recipients of the SAME group
// message can legitimately run concurrently: wipejob.go claims jobs with
// FOR UPDATE SKIP LOCKED specifically so multiple workers can each own a
// different job at once. Before this fix, sanitizeIngestReceipt and
// deleteGroupOutboxEntries did a bare read-modify-write
// (UPDATE ... IF EXISTS), where IF EXISTS guards only row existence, not
// the recipient_uins value each worker read. Two workers reading the same
// stale snapshot before either wrote back could silently lose one worker's
// removal: the second write would overwrite the first's, resurrecting an
// already-wiped recipient into a row that nothing would ever revisit again
// (each worker deletes its own erasure-index pointer once its own call
// returns successfully).
//
// The fix (scyllastore.go: sanitizeGroupIngestRecipients,
// sanitizeGroupOutboxRecipients) conditions every recipient-list UPDATE on
// the exact previously-read value -- an explicit bounded compare-and-set
// retry loop, not Scylla collection subtraction (whose interaction with
// USING TTL was not verified against this project's real Scylla version).
//
// These tests prove the fix at three levels:
//   - deterministic: call the single-CAS-attempt building block directly
//     with two conflicting reads of the same stale snapshot and prove
//     exactly one applies;
//   - real concurrent, one survivor: run two full wipes from goroutines
//     released by a shared barrier, repeated multiple times, against both
//     message_ingest and group_message_outbox, always leaving one
//     recipient behind to prove convergence;
//   - real concurrent, full exhaustion: the same shared-barrier release,
//     but wiping BOTH of a row's only two recipients at once, driving the
//     group-exhaustion/terminalize CAS branch in
//     sanitizeGroupIngestRecipients and the empty-list DELETE branch in
//     sanitizeGroupOutboxRecipients -- statement shapes no other test
//     exercises -- across the TTL, no-TTL, and already-expired paths the
//     schema permits.
//
// Several subtests deliberately leave a uin's erasure index pointing at a
// row that was never successfully cleaned up (unrecognized message_kind,
// exhausted CAS retries, a cancelled context) -- that is the exact
// behavior under test: a failed wipe step must not delete the index entry
// that lets a retry find the row again. Each subtest therefore uses its
// own disjoint block of uins (see freshUINs), never reusing one a prior
// subtest may have left in a deliberately-unfinished state.
package handlers

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gocql/gocql"
)

// concurrencyRepeatCount bounds how many times the fast (long-TTL,
// no-wall-clock-wait) concurrent-race convergence tests repeat. Each
// repetition uses a freshly seeded row, so a repeat only ever adds
// coverage against scheduling-dependent interleavings; it never depends on
// a previous repeat's outcome.
const concurrencyRepeatCount = 5

// newAcceptanceScyllaSession opens a real Scylla session against the
// disposable acceptance stack, mirroring the exact bootstrap sequence
// TestAcceptanceFullStack and TestAcceptanceGroupRecipientWipeTTLBehavior
// already use (kept local rather than extracted into a shared helper, to
// keep this addition self-contained and not touch the pre-existing
// acceptance test file).
func newAcceptanceScyllaSession(t *testing.T, ctx context.Context) *gocql.Session {
	t.Helper()
	scyllaHosts := acceptanceScyllaHosts(t)
	bootstrapCluster := gocql.NewCluster(scyllaHosts...)
	bootstrapCluster.Timeout = 10 * time.Second
	bootstrapCluster.ConnectTimeout = 10 * time.Second
	bootstrapSession, err := bootstrapCluster.CreateSession()
	if err != nil {
		t.Fatalf("Scylla unreachable at %v: %v", scyllaHosts, err)
	}
	if err := bootstrapSession.Query(`CREATE KEYSPACE IF NOT EXISTS iceq WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}`).WithContext(ctx).Exec(); err != nil {
		bootstrapSession.Close()
		t.Fatalf("Scylla keyspace creation failed: %v", err)
	}
	bootstrapSession.Close()

	scyllaCluster := gocql.NewCluster(scyllaHosts...)
	scyllaCluster.Keyspace = "iceq"
	scyllaCluster.Consistency = gocql.LocalQuorum
	scyllaCluster.Timeout = 10 * time.Second
	scyllaCluster.ConnectTimeout = 10 * time.Second
	session, err := scyllaCluster.CreateSession()
	if err != nil {
		t.Fatalf("Scylla unreachable at %v: %v", scyllaHosts, err)
	}
	return session
}

// runReleasedTogether starts len(fns) goroutines and blocks every one of
// them at a shared barrier until all have reached it, then releases them in
// the same instant -- maximizing real overlap on the subsequent Scylla
// calls instead of relying on incidental goroutine-launch scheduling.
// Errors are collected per-goroutine (never via t.Fatal from inside a
// goroutine, which the testing package does not support) and returned in
// launch order.
func runReleasedTogether(fns ...func() error) []error {
	var ready sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, len(fns))
	var done sync.WaitGroup
	for i, fn := range fns {
		i, fn := i, fn
		ready.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			errs[i] = fn()
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	return errs
}

func TestAcceptanceGroupRecipientConcurrentWipeNeverResurrects(t *testing.T) {
	requireAcceptanceEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	session := newAcceptanceScyllaSession(t, ctx)
	defer session.Close()
	applyScyllaSchema(t, session)

	msgStore, err := NewScyllaMessageStore(session)
	if err != nil {
		t.Fatalf("create Scylla store: %v", err)
	}

	// freshUINs hands out a disjoint (uinA, uinB, uinC, senderUIN) quadruple
	// per call. Subtests never share a uin block: several subtests below
	// deliberately leave a uin's erasure index pointing at a row that was
	// never successfully cleaned up (that IS the behavior under test), and
	// reusing uins across subtests would make a later subtest's wipe trip
	// over an earlier subtest's intentionally-unfinished row instead of
	// exercising its own. Not parallel, so a plain counter is safe.
	nextBase := int64(930000)
	freshUINs := func() (uinA, uinB, uinC, senderUIN int64) {
		nextBase += 10
		return nextBase + 1, nextBase + 2, nextBase + 3, nextBase + 4
	}

	seedGroupIngestRow := func(t *testing.T, senderUIN int64, recipients []int64, clientID string, ttlSeconds int) (expiresAt time.Time, msgID gocql.UUID) {
		t.Helper()
		groupID, err := gocql.RandomUUID()
		if err != nil {
			t.Fatal(err)
		}
		msgID, err = gocql.RandomUUID()
		if err != nil {
			t.Fatal(err)
		}
		createdAt := time.Now().UTC().Truncate(time.Millisecond)
		expiresAt = createdAt.Add(time.Duration(ttlSeconds) * time.Second)
		envelope := []byte("concurrency-check-envelope")
		hash := sha256.Sum256(envelope)
		if err := session.Query(`INSERT INTO message_ingest
			(sender_uin, client_id, message_kind, group_id, crypto_epoch, recipient_uins, envelope, envelope_hash, message_id, created_at, expires_at, state, owner_token, lease_until)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL ?`,
			senderUIN, clientID, "group", groupID, int64(1), recipients,
			envelope, hash[:], msgID, createdAt, expiresAt, "stored", msgID, createdAt, ttlSeconds,
		).WithContext(ctx).Exec(); err != nil {
			t.Fatalf("seed message_ingest: %v", err)
		}
		for _, indexUIN := range append(append([]int64(nil), recipients...), senderUIN) {
			if err := session.Query(`INSERT INTO message_ingest_erasure_index (uin, sender_uin, client_id) VALUES (?, ?, ?) USING TTL ?`,
				indexUIN, senderUIN, clientID, ttlSeconds).WithContext(ctx).Exec(); err != nil {
				t.Fatalf("seed message_ingest_erasure_index (uin %d): %v", indexUIN, err)
			}
		}
		return expiresAt, msgID
	}

	readGroupIngestRow := func(t *testing.T, senderUIN int64, clientID string) (found bool, recipients []int64, sanitized bool, state string, expiresAt time.Time) {
		t.Helper()
		iter := session.Query(`SELECT recipient_uins, recipient_set_sanitized, state, expires_at FROM message_ingest WHERE sender_uin = ? AND client_id = ?`, senderUIN, clientID).WithContext(ctx).Iter()
		found = iter.Scan(&recipients, &sanitized, &state, &expiresAt)
		if err := iter.Close(); err != nil {
			t.Fatalf("read message_ingest: %v", err)
		}
		return
	}

	countIngestErasureIndex := func(t *testing.T, uin int64) int {
		t.Helper()
		var count int
		iter := session.Query(`SELECT COUNT(*) FROM message_ingest_erasure_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
		iter.Scan(&count)
		if err := iter.Close(); err != nil {
			t.Fatalf("count message_ingest_erasure_index: %v", err)
		}
		return count
	}

	readIngestTombstoneFields := func(t *testing.T, senderUIN int64, clientID string) (receiverUIN int64, conversationID string, envelope, envelopeHash []byte) {
		t.Helper()
		iter := session.Query(`SELECT receiver_uin, conversation_id, envelope, envelope_hash FROM message_ingest WHERE sender_uin = ? AND client_id = ?`, senderUIN, clientID).WithContext(ctx).Iter()
		iter.Scan(&receiverUIN, &conversationID, &envelope, &envelopeHash)
		if err := iter.Close(); err != nil {
			t.Fatalf("read message_ingest tombstone fields: %v", err)
		}
		return
	}

	seedGroupOutboxRow := func(t *testing.T, senderUIN int64, recipients []int64, clientIDSuffix string, ttlSeconds int) (bucket int8, createdAt time.Time, msgID gocql.UUID) {
		t.Helper()
		groupID, err := gocql.RandomUUID()
		if err != nil {
			t.Fatal(err)
		}
		msgID, err = gocql.RandomUUID()
		if err != nil {
			t.Fatal(err)
		}
		createdAt = time.Now().UTC().Truncate(time.Millisecond)
		bucket = int8(msgID[0] & 15)
		expiresAt := createdAt.Add(time.Duration(ttlSeconds) * time.Second)
		if err := session.Query(`INSERT INTO group_message_outbox
			(bucket, created_at, message_id, group_id, sender_uin, client_id, crypto_epoch, recipient_uins, envelope, envelope_hash, state, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL ?`,
			bucket, createdAt, msgID, groupID, senderUIN, "outbox-"+clientIDSuffix, 1,
			recipients, []byte("env"), []byte("hash12345678901234567890123456789012"), "pending", expiresAt, ttlSeconds,
		).WithContext(ctx).Exec(); err != nil {
			t.Fatalf("seed group_message_outbox: %v", err)
		}
		for _, indexUIN := range recipients {
			role := "recipient"
			if err := session.Query(`INSERT INTO group_message_outbox_erasure_index (uin, bucket, created_at, message_id, role) VALUES (?, ?, ?, ?, ?) USING TTL ?`,
				indexUIN, bucket, createdAt, msgID, role, ttlSeconds).WithContext(ctx).Exec(); err != nil {
				t.Fatalf("seed group_message_outbox_erasure_index (uin %d): %v", indexUIN, err)
			}
		}
		if err := session.Query(`INSERT INTO group_message_outbox_erasure_index (uin, bucket, created_at, message_id, role) VALUES (?, ?, ?, ?, ?) USING TTL ?`,
			senderUIN, bucket, createdAt, msgID, "sender", ttlSeconds).WithContext(ctx).Exec(); err != nil {
			t.Fatalf("seed group_message_outbox_erasure_index (sender %d): %v", senderUIN, err)
		}
		return bucket, createdAt, msgID
	}

	readGroupOutboxRow := func(t *testing.T, bucket int8, createdAt time.Time, msgID gocql.UUID) (found bool, recipients []int64) {
		t.Helper()
		iter := session.Query(`SELECT recipient_uins FROM group_message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?`, bucket, createdAt, msgID).WithContext(ctx).Iter()
		found = iter.Scan(&recipients)
		if err := iter.Close(); err != nil {
			t.Fatalf("read group_message_outbox: %v", err)
		}
		return
	}

	countOutboxErasureIndex := func(t *testing.T, uin int64) int {
		t.Helper()
		var count int
		iter := session.Query(`SELECT COUNT(*) FROM group_message_outbox_erasure_index WHERE uin = ?`, uin).WithContext(ctx).Iter()
		iter.Scan(&count)
		if err := iter.Close(); err != nil {
			t.Fatalf("count group_message_outbox_erasure_index: %v", err)
		}
		return count
	}

	// ---------------------------------------------------------------------
	// Deterministic: two stale readers of the identical snapshot, exactly
	// one CAS attempt applies. This exercises sanitizeGroupIngestRecipients
	// directly (the single-attempt building block), independent of Go
	// scheduling -- both calls are handed the SAME previousRecipients value,
	// which is exactly the dangerous interleaving the fix defends against.
	// ---------------------------------------------------------------------
	t.Run("single CAS attempt: two stale readers of the same snapshot, exactly one wins", func(t *testing.T) {
		uinA, uinB, uinC, senderUIN := freshUINs()
		clientID := "det-single-cas"
		expiresAt, _ := seedGroupIngestRow(t, senderUIN, []int64{uinA, uinB, uinC}, clientID, 3600)
		staleSnapshot := []int64{uinA, uinB, uinC}
		remaining := remainingIngestTTLSeconds(expiresAt, time.Now().UTC())

		appliedA, errA := msgStore.sanitizeGroupIngestRecipients(ctx, senderUIN, clientID, uinA, staleSnapshot, remaining)
		if errA != nil {
			t.Fatalf("worker A CAS attempt: %v", errA)
		}
		appliedB, errB := msgStore.sanitizeGroupIngestRecipients(ctx, senderUIN, clientID, uinB, staleSnapshot, remaining)
		if errB != nil {
			t.Fatalf("worker B CAS attempt: %v", errB)
		}
		if appliedA == appliedB {
			t.Fatalf("expected exactly one of two stale-snapshot CAS attempts to apply, got appliedA=%v appliedB=%v", appliedA, appliedB)
		}

		// Whichever lost must not have corrupted the row: the winner's
		// removal must be intact, not overwritten.
		found, recipients, _, _, _ := readGroupIngestRow(t, senderUIN, clientID)
		if !found {
			t.Fatal("row unexpectedly gone after a single CAS attempt")
		}
		loserUIN, winnerUIN := uinB, uinA
		if appliedB {
			loserUIN, winnerUIN = uinA, uinB
		}
		for _, r := range recipients {
			if r == winnerUIN {
				t.Fatalf("winning worker's own uin %d is still present in recipient_uins %v", winnerUIN, recipients)
			}
		}
		found = false
		for _, r := range recipients {
			if r == loserUIN {
				found = true
			}
		}
		if !found {
			t.Fatalf("losing worker's uin %d was removed by its own failed CAS -- applied=false must mean no write occurred", loserUIN)
		}
	})

	// ---------------------------------------------------------------------
	// Real concurrent, repeated: two goroutines wipe A and B at the same
	// instant via the real public wipe entry points. Covers message_ingest.
	// ---------------------------------------------------------------------
	t.Run("message_ingest: concurrent wipe of two recipients converges to the exact survivor, repeated", func(t *testing.T) {
		uinA, uinB, uinC, senderUIN := freshUINs()
		for i := 0; i < concurrencyRepeatCount; i++ {
			clientID := fmt.Sprintf("real-concurrent-ingest-%d", i)
			expiresAt, _ := seedGroupIngestRow(t, senderUIN, []int64{uinA, uinB, uinC}, clientID, 3600)

			confirmAbsent := func(uin int64) error {
				found, recipients, _, _, _ := readGroupIngestRow(t, senderUIN, clientID)
				if !found {
					return fmt.Errorf("row missing while confirming uin %d absent", uin)
				}
				for _, r := range recipients {
					if r == uin {
						return fmt.Errorf("uin %d still present in recipient_uins %v immediately after its own wipe call returned success", uin, recipients)
					}
				}
				return nil
			}
			wipeAndConfirm := func(uin int64) func() error {
				return func() error {
					if err := msgStore.DeleteUserMessages(ctx, uin); err != nil {
						return fmt.Errorf("DeleteUserMessages(%d): %w", uin, err)
					}
					// Requirement: a wipe job must never report success
					// before its own uin is confirmed absent.
					return confirmAbsent(uin)
				}
			}
			for j, err := range runReleasedTogether(wipeAndConfirm(uinA), wipeAndConfirm(uinB)) {
				if err != nil {
					t.Fatalf("[iter %d] concurrent wipe worker %d: %v", i, j, err)
				}
			}

			found, recipients, sanitized, state, gotExpiresAt := readGroupIngestRow(t, senderUIN, clientID)
			if !found {
				t.Fatalf("[iter %d] row gone after concurrent wipe of A and B -- C must still have it", i)
			}
			if len(recipients) != 1 || recipients[0] != uinC {
				t.Fatalf("[iter %d] recipient_uins = %v, want exactly [%d]", i, recipients, uinC)
			}
			if !sanitized {
				t.Fatalf("[iter %d] recipient_set_sanitized = false, want true", i)
			}
			if state != "stored" {
				t.Fatalf("[iter %d] state = %q, want unchanged %q -- group was not exhausted, C survives", i, state, "stored")
			}
			if !gotExpiresAt.Equal(expiresAt) {
				t.Fatalf("[iter %d] expires_at = %v, want unchanged %v", i, gotExpiresAt, expiresAt)
			}
			if got := countIngestErasureIndex(t, uinA); got != 0 {
				t.Fatalf("[iter %d] message_ingest_erasure_index for wiped uin A still has %d rows", i, got)
			}
			if got := countIngestErasureIndex(t, uinB); got != 0 {
				t.Fatalf("[iter %d] message_ingest_erasure_index for wiped uin B still has %d rows", i, got)
			}
			if got := countIngestErasureIndex(t, uinC); got == 0 {
				t.Fatalf("[iter %d] message_ingest_erasure_index for surviving uin C was incorrectly removed", i)
			}
		}
	})

	// ---------------------------------------------------------------------
	// Real concurrent, repeated: same race, covers group_message_outbox.
	// ---------------------------------------------------------------------
	t.Run("group_message_outbox: concurrent wipe of two recipients converges to the exact survivor, repeated", func(t *testing.T) {
		uinA, uinB, uinC, senderUIN := freshUINs()
		for i := 0; i < concurrencyRepeatCount; i++ {
			bucket, createdAt, msgID := seedGroupOutboxRow(t, senderUIN, []int64{uinA, uinB, uinC}, fmt.Sprintf("real-concurrent-%d", i), 3600)

			confirmAbsent := func(uin int64) error {
				found, recipients := readGroupOutboxRow(t, bucket, createdAt, msgID)
				if !found {
					return fmt.Errorf("row missing while confirming uin %d absent", uin)
				}
				for _, r := range recipients {
					if r == uin {
						return fmt.Errorf("uin %d still present in recipient_uins %v immediately after its own wipe call returned success", uin, recipients)
					}
				}
				return nil
			}
			wipeAndConfirm := func(uin int64) func() error {
				return func() error {
					if err := msgStore.DeleteUserGroupMessages(ctx, uin); err != nil {
						return fmt.Errorf("DeleteUserGroupMessages(%d): %w", uin, err)
					}
					return confirmAbsent(uin)
				}
			}
			for j, err := range runReleasedTogether(wipeAndConfirm(uinA), wipeAndConfirm(uinB)) {
				if err != nil {
					t.Fatalf("[iter %d] concurrent wipe worker %d: %v", i, j, err)
				}
			}

			found, recipients := readGroupOutboxRow(t, bucket, createdAt, msgID)
			if !found {
				t.Fatalf("[iter %d] row gone after concurrent wipe of A and B -- C must still have it", i)
			}
			if len(recipients) != 1 || recipients[0] != uinC {
				t.Fatalf("[iter %d] recipient_uins = %v, want exactly [%d]", i, recipients, uinC)
			}
			if got := countOutboxErasureIndex(t, uinA); got != 0 {
				t.Fatalf("[iter %d] group_message_outbox_erasure_index for wiped uin A still has %d rows", i, got)
			}
			if got := countOutboxErasureIndex(t, uinB); got != 0 {
				t.Fatalf("[iter %d] group_message_outbox_erasure_index for wiped uin B still has %d rows", i, got)
			}
			if got := countOutboxErasureIndex(t, uinC); got == 0 {
				t.Fatalf("[iter %d] group_message_outbox_erasure_index for surviving uin C was incorrectly removed", i)
			}
		}
	})

	// ---------------------------------------------------------------------
	// Repeated cleanup after convergence remains idempotent: a retried wipe
	// job (crash-and-restart, or a stale erasure-index entry) for a uin
	// that has already been fully processed must be a safe no-op.
	// ---------------------------------------------------------------------
	t.Run("repeated cleanup after convergence remains idempotent", func(t *testing.T) {
		uinA, uinB, uinC, senderUIN := freshUINs()
		clientID := "idempotent-repeat"
		seedGroupIngestRow(t, senderUIN, []int64{uinA, uinB, uinC}, clientID, 3600)
		if err := msgStore.DeleteUserMessages(ctx, uinA); err != nil {
			t.Fatalf("first wipe of A: %v", err)
		}
		found, firstRecipients, firstSanitized, firstState, firstExpiresAt := readGroupIngestRow(t, senderUIN, clientID)
		if !found {
			t.Fatal("row gone after first wipe")
		}

		// Repeat: same uin, same row, no other concurrent writer this time.
		if err := msgStore.DeleteUserMessages(ctx, uinA); err != nil {
			t.Fatalf("repeated wipe of A: %v", err)
		}
		found, secondRecipients, secondSanitized, secondState, secondExpiresAt := readGroupIngestRow(t, senderUIN, clientID)
		if !found {
			t.Fatal("row gone after repeated wipe")
		}
		if len(secondRecipients) != len(firstRecipients) {
			t.Fatalf("repeated wipe changed recipient_uins: first=%v second=%v", firstRecipients, secondRecipients)
		}
		for idx := range firstRecipients {
			if firstRecipients[idx] != secondRecipients[idx] {
				t.Fatalf("repeated wipe changed recipient_uins: first=%v second=%v", firstRecipients, secondRecipients)
			}
		}
		if firstSanitized != secondSanitized || firstState != secondState || !firstExpiresAt.Equal(secondExpiresAt) {
			t.Fatalf("repeated wipe changed row state: first=(sanitized=%v state=%q expiresAt=%v) second=(sanitized=%v state=%q expiresAt=%v)",
				firstSanitized, firstState, firstExpiresAt, secondSanitized, secondState, secondExpiresAt)
		}
		if got := countIngestErasureIndex(t, uinA); got != 0 {
			t.Fatalf("repeated wipe recreated the erasure index for an already-wiped uin: %d rows", got)
		}
	})

	// ---------------------------------------------------------------------
	// Bounded retry exhaustion must fail the wipe step, never report false
	// success. Six tight-loop adversary goroutines continuously change
	// recipient_uins for the whole duration of the main call, so every one
	// of its bounded attempts reads a value that is stale by the time its
	// own CAS lands.
	// ---------------------------------------------------------------------
	// CAS retry under synchronized contention: forcing real exhaustion
	// against real Scylla is inherently a timing race -- adversaries and
	// the call under test both need a network round trip per attempt, so
	// whether the main call's CAS wins on a given attempt against 6
	// concurrent adversaries can never be made deterministic without
	// instrumenting production code (excluded -- see boundedCASRetry's own
	// deterministic unit test in scyllastore_retry_test.go, which forces
	// exhaustion with a fake, network-free attempt function instead). This
	// test only asserts the safety contract that must hold regardless of
	// which outcome the race happens to produce: never report success
	// while the wiped uin remains, never resurrect it, never extend TTL,
	// and never delete the erasure index before absence is confirmed.
	//
	// A synchronization barrier guarantees every adversary is actively
	// looping before the call under test starts (fixing the previous
	// version's flakiness, which came from occasionally letting the main
	// call's first attempt land before any real contention existed) --
	// but the barrier only guarantees contention is present, not which
	// side wins a given round, so the assertion below accepts either
	// outcome rather than trying to force one.
	t.Run("CAS retry under synchronized contention: safety holds regardless of outcome", func(t *testing.T) {
		uinA, uinB, uinC, senderUIN := freshUINs()
		clientID := "exhaustion-safety-check"
		seedGroupIngestRow(t, senderUIN, []int64{uinA, uinB, uinC}, clientID, 3600)

		const adversaryCount = 6
		dummyBase := int64(800000000)
		var adversariesReady sync.WaitGroup
		adversaryStart := make(chan struct{})
		stop := make(chan struct{})
		var adversaries sync.WaitGroup
		for a := 0; a < adversaryCount; a++ {
			a := a
			adversariesReady.Add(1)
			adversaries.Add(1)
			go func() {
				defer adversaries.Done()
				adversariesReady.Done()
				<-adversaryStart
				for {
					select {
					case <-stop:
						return
					default:
					}
					var current []int64
					iter := session.Query(`SELECT recipient_uins FROM message_ingest WHERE sender_uin = ? AND client_id = ?`, senderUIN, clientID).WithContext(ctx).Iter()
					iter.Scan(&current)
					_ = iter.Close()
					// Append-only, derived from whatever this read actually
					// saw -- never reset to a hardcoded list. A version of
					// this adversary used to reset to []int64{uinA, uinB,
					// uinC} on alternating iterations, which could replay a
					// stale pre-removal snapshot and successfully CAS uinA
					// back in AFTER the call under test had already
					// legitimately, successfully removed it -- a resurrection
					// caused entirely by this goroutine's own hardcoded reset,
					// not by any defect in the CAS retry logic under test. A
					// real concurrent writer wouldn't undo another worker's
					// removal either; it would only contend over its own
					// unrelated changes, which append-only faithfully models.
					next := append(append([]int64(nil), current...), dummyBase+int64(a))
					// Best-effort: a failed CAS just means we try again
					// next loop iteration with a fresh read. Errors are
					// deliberately ignored -- this goroutine's only job is
					// to keep the value churning.
					_, _ = session.Query(`UPDATE message_ingest SET recipient_uins = ? WHERE sender_uin = ? AND client_id = ? IF recipient_uins = ?`,
						next, senderUIN, clientID, current).WithContext(ctx).Consistency(gocql.Quorum).SerialConsistency(gocql.Serial).MapScanCAS(map[string]any{})
				}
			}()
		}
		// Wait for every adversary to be actively looping before starting
		// the call under test, instead of relying on scheduling luck to
		// land contention on its very first attempt.
		adversariesReady.Wait()
		close(adversaryStart)

		err := msgStore.DeleteUserMessages(ctx, uinA)
		close(stop)
		adversaries.Wait()

		if err == nil {
			// Claimed success: must be truthful, not merely the absence of
			// an error.
			found, recipients, _, _, _ := readGroupIngestRow(t, senderUIN, clientID)
			if !found {
				t.Fatal("row missing after a claimed-successful wipe under contention")
			}
			for _, r := range recipients {
				if r == uinA {
					t.Fatalf("DeleteUserMessages reported success but uin %d is still present in recipient_uins %v -- success must never be reported while the wiped uin remains", uinA, recipients)
				}
			}
			if got := countIngestErasureIndex(t, uinA); got != 0 {
				t.Fatalf("DeleteUserMessages reported success but the erasure index for uin %d still has %d rows -- index must be removed once absence is confirmed", uinA, got)
			}
			var ttl int
			iter := session.Query(`SELECT TTL(recipient_set_sanitized) FROM message_ingest WHERE sender_uin = ? AND client_id = ?`, senderUIN, clientID).WithContext(ctx).Iter()
			iter.Scan(&ttl)
			if err := iter.Close(); err != nil {
				t.Fatalf("read TTL: %v", err)
			}
			if ttl <= 0 || ttl > 3600 {
				t.Fatalf("TTL(recipient_set_sanitized) after a claimed-successful wipe under contention = %d, want in (0, 3600] -- success must not extend or drop TTL", ttl)
			}
			return
		}

		// Claimed failure: must be the documented, retryable exhaustion
		// error -- never a silent or ambiguous one -- and the erasure
		// index must survive so a retried wipe job can find this row
		// again. deleteIngestReceipts must NOT have deleted uinA's own
		// erasure-index entry in this branch.
		if !strings.Contains(err.Error(), "exhausted") || !strings.Contains(err.Error(), "CAS") {
			t.Fatalf("error = %q, want it to explain bounded CAS-retry exhaustion so the wipe job can be identified and retried", err.Error())
		}
		if got := countIngestErasureIndex(t, uinA); got == 0 {
			t.Fatal("erasure index for uin A was deleted despite the wipe step failing -- a retried wipe job would never find this row again")
		}
	})

	// ---------------------------------------------------------------------
	// Context cancellation must be reported as an error, never swallowed
	// into a false success or a silent no-op.
	// ---------------------------------------------------------------------
	t.Run("context cancellation during CAS retry is reported, not swallowed", func(t *testing.T) {
		uinA, uinB, uinC, senderUIN := freshUINs()
		clientID := "cancellation-check"
		seedGroupIngestRow(t, senderUIN, []int64{uinA, uinB, uinC}, clientID, 3600)

		cancelledCtx, cancelNow := context.WithCancel(context.Background())
		cancelNow()

		err := msgStore.DeleteUserMessages(cancelledCtx, uinA)
		if err == nil {
			t.Fatal("expected an error when the context is already cancelled, got nil")
		}

		// The row must be completely untouched -- a cancelled context must
		// never be allowed to partially apply a mutation.
		found, recipients, sanitized, _, _ := readGroupIngestRow(t, senderUIN, clientID)
		if !found {
			t.Fatal("row gone after a cancelled-context wipe attempt")
		}
		if len(recipients) != 3 {
			t.Fatalf("recipient_uins = %v after a cancelled-context wipe attempt, want the original 3 untouched", recipients)
		}
		if sanitized {
			t.Fatal("recipient_set_sanitized = true after a cancelled-context wipe attempt, want untouched (false)")
		}
	})

	// ---------------------------------------------------------------------
	// message_kind must fail closed on an unrecognized value, not be
	// silently treated as "group".
	// ---------------------------------------------------------------------
	t.Run("unknown message_kind fails closed instead of being treated as group", func(t *testing.T) {
		uinA, _, _, senderUIN := freshUINs()
		clientID := "unknown-kind-check"
		createdAt := time.Now().UTC().Truncate(time.Millisecond)
		msgID, err := gocql.RandomUUID()
		if err != nil {
			t.Fatal(err)
		}
		envelope := []byte("unknown-kind-envelope")
		hash := sha256.Sum256(envelope)
		if err := session.Query(`INSERT INTO message_ingest
			(sender_uin, client_id, message_kind, receiver_uin, conversation_id, envelope, envelope_hash, message_id, created_at, state, owner_token, lease_until)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL 3600`,
			senderUIN, clientID, "carrier-pigeon", uinA, "conv-unknown-kind",
			envelope, hash[:], msgID, createdAt, "stored", msgID, createdAt,
		).WithContext(ctx).Exec(); err != nil {
			t.Fatalf("seed message_ingest with unknown kind: %v", err)
		}
		if err := session.Query(`INSERT INTO message_ingest_erasure_index (uin, sender_uin, client_id) VALUES (?, ?, ?) USING TTL 3600`,
			uinA, senderUIN, clientID).WithContext(ctx).Exec(); err != nil {
			t.Fatalf("seed message_ingest_erasure_index: %v", err)
		}

		err = msgStore.DeleteUserMessages(ctx, uinA)
		if err == nil {
			t.Fatal("expected an error for an unrecognized message_kind, got nil -- it must not be silently treated as a group receipt")
		}
		if !strings.Contains(err.Error(), "message_kind") {
			t.Fatalf("error = %q, want it to name the unrecognized message_kind", err.Error())
		}

		// Fail closed: the row must be entirely untouched, not partially
		// mutated as if it were a group receipt.
		var recipients []int64
		var state string
		iter := session.Query(`SELECT recipient_uins, state FROM message_ingest WHERE sender_uin = ? AND client_id = ?`, senderUIN, clientID).WithContext(ctx).Iter()
		found := iter.Scan(&recipients, &state)
		if err := iter.Close(); err != nil {
			t.Fatalf("read unknown-kind row: %v", err)
		}
		if !found {
			t.Fatal("unknown-kind row was deleted -- fail-closed must leave it untouched, not remove it")
		}
		if state != "stored" {
			t.Fatalf("unknown-kind row state = %q, want unchanged %q", state, "stored")
		}
		if len(recipients) != 0 {
			t.Fatalf("unknown-kind row recipient_uins = %v, want untouched (never set for a direct-shaped row)", recipients)
		}
	})

	// ---------------------------------------------------------------------
	// The original expiry must survive a concurrent race: neither worker's
	// CAS write may extend the row's TTL or make it permanent. Proven
	// against real wall-clock expiry for group_message_outbox (no atomic
	// sibling column to read TTL() from -- recipient_uins is a non-frozen
	// LIST, which Scylla's TTL() function rejects), and via TTL() on the
	// atomic recipient_set_sanitized column for message_ingest.
	// ---------------------------------------------------------------------
	t.Run("expiry is not extended by a concurrent race", func(t *testing.T) {
		t.Run("message_ingest", func(t *testing.T) {
			uinA, uinB, uinC, senderUIN := freshUINs()
			clientID := "expiry-ingest"
			seedGroupIngestRow(t, senderUIN, []int64{uinA, uinB, uinC}, clientID, 3600)

			wipe := func(uin int64) func() error {
				return func() error { return msgStore.DeleteUserMessages(ctx, uin) }
			}
			for j, err := range runReleasedTogether(wipe(uinA), wipe(uinB)) {
				if err != nil {
					t.Fatalf("concurrent wipe worker %d: %v", j, err)
				}
			}

			var ttl int
			iter := session.Query(`SELECT TTL(recipient_set_sanitized) FROM message_ingest WHERE sender_uin = ? AND client_id = ?`, senderUIN, clientID).WithContext(ctx).Iter()
			iter.Scan(&ttl)
			if err := iter.Close(); err != nil {
				t.Fatalf("read TTL: %v", err)
			}
			if ttl <= 0 || ttl > 3600 {
				t.Fatalf("TTL(recipient_set_sanitized) after concurrent wipe = %d, want in (0, 3600] -- a concurrent race must not extend TTL or make the row permanent", ttl)
			}
		})

		t.Run("group_message_outbox", func(t *testing.T) {
			uinA, uinB, uinC, senderUIN := freshUINs()
			const (
				originalTTL  = 8 // seconds
				pollInterval = 200 * time.Millisecond
				// The row must still be alive this far short of the
				// original TTL -- proves the concurrent race did not
				// truncate the TTL toward zero.
				aliveThroughMargin = 2 * time.Second
				// How far past the original TTL the row may still be
				// observed before concluding the race made it permanent or
				// extended it. Generous enough to absorb scheduling jitter.
				expiryMargin = 5 * time.Second
			)
			start := time.Now()
			bucket, createdAt, msgID := seedGroupOutboxRow(t, senderUIN, []int64{uinA, uinB, uinC}, "expiry", originalTTL)

			wipe := func(uin int64) func() error {
				return func() error { return msgStore.DeleteUserGroupMessages(ctx, uin) }
			}
			for j, err := range runReleasedTogether(wipe(uinA), wipe(uinB)) {
				if err != nil {
					t.Fatalf("concurrent wipe worker %d: %v", j, err)
				}
			}

			found, recipients := readGroupOutboxRow(t, bucket, createdAt, msgID)
			if !found {
				t.Fatal("row gone immediately after concurrent wipe -- TTL must not be dropped near-zero")
			}
			if len(recipients) != 1 || recipients[0] != uinC {
				t.Fatalf("recipient_uins after concurrent wipe = %v, want exactly [%d]", recipients, uinC)
			}

			aliveDeadline := originalTTL*time.Second - aliveThroughMargin
			earlyElapsed, wentAwayEarly := pollUntil(start, aliveDeadline, pollInterval, func() bool {
				found, _ := readGroupOutboxRow(t, bucket, createdAt, msgID)
				return !found
			})
			if wentAwayEarly {
				t.Fatalf("row expired early, %s after start (original TTL was %ds) -- concurrent race truncated the TTL instead of preserving it", earlyElapsed, originalTTL)
			}

			expiryDeadline := originalTTL*time.Second + expiryMargin
			_, becameGone := pollUntil(start, expiryDeadline, pollInterval, func() bool {
				found, _ := readGroupOutboxRow(t, bucket, createdAt, msgID)
				return !found
			})
			if !becameGone {
				stillFound, stillRecipients := readGroupOutboxRow(t, bucket, createdAt, msgID)
				t.Fatalf("row still alive past its original %ds TTL plus %s margin -- concurrent race made it permanent or extended it; found=%v recipients=%v",
					originalTTL, expiryMargin, stillFound, stillRecipients)
			}
		})
	})

	// ---------------------------------------------------------------------
	// Concurrent wipe of the LAST TWO recipients (full exhaustion). Every
	// test above deliberately leaves one survivor (3 recipients, wipe 2) to
	// prove convergence -- none of them ever drive a row's recipient list
	// to zero, so the group-exhaustion/terminalize CAS branch in
	// sanitizeGroupIngestRecipients (the 7-column UPDATE ... IF
	// recipient_uins = ?) and the empty-list DELETE branch in
	// sanitizeGroupOutboxRecipients had never actually run against real
	// Scylla. These two subtests close that gap, each across the three
	// paths the schema permits: a row with time remaining, a row with no
	// expiry configured at all, and a row already past its own expiry.
	// ---------------------------------------------------------------------
	t.Run("message_ingest: concurrent wipe of the last two recipients terminalizes the row", func(t *testing.T) {
		// Sentinel values with no real user data: sentinelReceiverUIN is
		// negative (every real uin from freshUINs is positive and >=
		// 930001), and sentinelConversationID is an obviously-synthetic
		// string. Seeded into every variant below and confirmed present
		// BEFORE each wipe, so the post-wipe "cleared" assertions prove the
		// terminal CAS statement actively clears these columns instead of
		// trivially passing against a column that was already empty.
		const (
			sentinelReceiverUIN    = int64(-1)
			sentinelConversationID = "sentinel:not-real-user-data"
		)

		t.Run("row has time remaining", func(t *testing.T) {
			uinA, uinB, _, senderUIN := freshUINs()
			clientID := "exhaustion-ingest-ttl"
			groupID, err := gocql.RandomUUID()
			if err != nil {
				t.Fatal(err)
			}
			msgID, err := gocql.RandomUUID()
			if err != nil {
				t.Fatal(err)
			}
			createdAt := time.Now().UTC().Truncate(time.Millisecond)
			expiresAt := createdAt.Add(3600 * time.Second)
			envelope := []byte("time-remaining-exhaustion-envelope")
			hash := sha256.Sum256(envelope)
			if err := session.Query(`INSERT INTO message_ingest
				(sender_uin, client_id, message_kind, receiver_uin, conversation_id, group_id, crypto_epoch, recipient_uins, envelope, envelope_hash, message_id, created_at, expires_at, state, owner_token, lease_until)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL 3600`,
				senderUIN, clientID, "group", sentinelReceiverUIN, sentinelConversationID, groupID, int64(1), []int64{uinA, uinB},
				envelope, hash[:], msgID, createdAt, expiresAt, "stored", msgID, createdAt,
			).WithContext(ctx).Exec(); err != nil {
				t.Fatalf("seed message_ingest: %v", err)
			}
			for _, indexUIN := range []int64{uinA, uinB, senderUIN} {
				if err := session.Query(`INSERT INTO message_ingest_erasure_index (uin, sender_uin, client_id) VALUES (?, ?, ?) USING TTL 3600`,
					indexUIN, senderUIN, clientID).WithContext(ctx).Exec(); err != nil {
					t.Fatalf("seed message_ingest_erasure_index (uin %d): %v", indexUIN, err)
				}
			}

			preReceiverUIN, preConversationID, preEnvelope, preEnvelopeHash := readIngestTombstoneFields(t, senderUIN, clientID)
			if preReceiverUIN != sentinelReceiverUIN || preConversationID != sentinelConversationID || len(preEnvelope) == 0 || len(preEnvelopeHash) == 0 {
				t.Fatalf("pre-wipe sentinel check failed: receiver_uin=%d conversation_id=%q envelope=%q envelope_hash=%x -- seeding did not persist the expected sentinels, post-wipe checks would be meaningless", preReceiverUIN, preConversationID, preEnvelope, preEnvelopeHash)
			}

			wipe := func(uin int64) func() error {
				return func() error { return msgStore.DeleteUserMessages(ctx, uin) }
			}
			for j, err := range runReleasedTogether(wipe(uinA), wipe(uinB)) {
				if err != nil {
					t.Fatalf("concurrent wipe worker %d: %v", j, err)
				}
			}

			found, recipients, sanitized, state, gotExpiresAt := readGroupIngestRow(t, senderUIN, clientID)
			if !found {
				t.Fatal("row gone after exhaustion wipe -- the PK (sender_uin, client_id) must persist as the minimum sender-scoped idempotency record")
			}
			if state != ingestRecipientErasedState {
				t.Fatalf("state = %q, want terminal %q", state, ingestRecipientErasedState)
			}
			if !sanitized {
				t.Fatal("recipient_set_sanitized = false, want true")
			}
			if len(recipients) != 0 {
				t.Fatalf("recipient_uins = %v, want empty -- both wiped recipients must be gone", recipients)
			}
			if !gotExpiresAt.Equal(expiresAt) {
				t.Fatalf("expires_at = %v, want unchanged original %v -- a retry must never extend TTL", gotExpiresAt, expiresAt)
			}
			receiverUIN, conversationID, gotEnvelope, gotEnvelopeHash := readIngestTombstoneFields(t, senderUIN, clientID)
			if receiverUIN != 0 {
				t.Fatalf("receiver_uin = %d, want actively cleared from sentinel %d", receiverUIN, sentinelReceiverUIN)
			}
			if conversationID != "" {
				t.Fatalf("conversation_id = %q, want actively cleared from sentinel %q", conversationID, sentinelConversationID)
			}
			if len(gotEnvelope) != 0 {
				t.Fatalf("envelope = %q, want cleared -- ciphertext must not survive terminalization", gotEnvelope)
			}
			if len(gotEnvelopeHash) != 0 {
				t.Fatalf("envelope_hash = %x, want cleared", gotEnvelopeHash)
			}
			if got := countIngestErasureIndex(t, uinA); got != 0 {
				t.Fatalf("message_ingest_erasure_index for wiped uin A still has %d rows", got)
			}
			if got := countIngestErasureIndex(t, uinB); got != 0 {
				t.Fatalf("message_ingest_erasure_index for wiped uin B still has %d rows", got)
			}

			var ttl int
			iter := session.Query(`SELECT TTL(recipient_set_sanitized) FROM message_ingest WHERE sender_uin = ? AND client_id = ?`, senderUIN, clientID).WithContext(ctx).Iter()
			iter.Scan(&ttl)
			if err := iter.Close(); err != nil {
				t.Fatalf("read TTL: %v", err)
			}
			if ttl <= 0 || ttl > 3600 {
				t.Fatalf("TTL(recipient_set_sanitized) after exhaustion = %d, want in (0, 3600] -- the terminal CAS write must preserve the original TTL, not extend or drop it", ttl)
			}

			// Retry both cleanups: idempotency and no resurrection.
			if err := msgStore.DeleteUserMessages(ctx, uinA); err != nil {
				t.Fatalf("repeated wipe of A: %v", err)
			}
			if err := msgStore.DeleteUserMessages(ctx, uinB); err != nil {
				t.Fatalf("repeated wipe of B: %v", err)
			}
			found, recipients, sanitized, state, gotExpiresAt = readGroupIngestRow(t, senderUIN, clientID)
			if !found {
				t.Fatal("row gone after repeated cleanup")
			}
			if state != ingestRecipientErasedState || !sanitized || len(recipients) != 0 || !gotExpiresAt.Equal(expiresAt) {
				t.Fatalf("repeated cleanup changed terminal state: state=%q sanitized=%v recipients=%v expiresAt=%v", state, sanitized, recipients, gotExpiresAt)
			}
			if got := countIngestErasureIndex(t, uinA); got != 0 {
				t.Fatalf("repeated wipe recreated the erasure index for wiped uin A: %d rows", got)
			}
			if got := countIngestErasureIndex(t, uinB); got != 0 {
				t.Fatalf("repeated wipe recreated the erasure index for wiped uin B: %d rows", got)
			}
		})

		t.Run("row has no expiry configured", func(t *testing.T) {
			uinA, uinB, _, senderUIN := freshUINs()
			clientID := "exhaustion-ingest-no-ttl"
			groupID, err := gocql.RandomUUID()
			if err != nil {
				t.Fatal(err)
			}
			msgID, err := gocql.RandomUUID()
			if err != nil {
				t.Fatal(err)
			}
			createdAt := time.Now().UTC().Truncate(time.Millisecond)
			envelope := []byte("no-ttl-exhaustion-envelope")
			hash := sha256.Sum256(envelope)
			// No "USING TTL" clause and no expires_at value: a permanent
			// receipt, which sanitizeIngestReceipt's expiresAt.IsZero()
			// check exists specifically to treat as "not expired" rather
			// than skip. Schema permits this: expires_at is a plain
			// nullable TIMESTAMP
			// (deploy/init/migrations/012_durable_message_ingest.cql).
			if err := session.Query(`INSERT INTO message_ingest
				(sender_uin, client_id, message_kind, receiver_uin, conversation_id, group_id, crypto_epoch, recipient_uins, envelope, envelope_hash, message_id, created_at, state, owner_token, lease_until)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				senderUIN, clientID, "group", sentinelReceiverUIN, sentinelConversationID, groupID, int64(1), []int64{uinA, uinB},
				envelope, hash[:], msgID, createdAt, "stored", msgID, createdAt,
			).WithContext(ctx).Exec(); err != nil {
				t.Fatalf("seed no-TTL message_ingest: %v", err)
			}
			for _, indexUIN := range []int64{uinA, uinB, senderUIN} {
				if err := session.Query(`INSERT INTO message_ingest_erasure_index (uin, sender_uin, client_id) VALUES (?, ?, ?) USING TTL 3600`,
					indexUIN, senderUIN, clientID).WithContext(ctx).Exec(); err != nil {
					t.Fatalf("seed message_ingest_erasure_index (uin %d): %v", indexUIN, err)
				}
			}

			preReceiverUIN, preConversationID, preEnvelope, preEnvelopeHash := readIngestTombstoneFields(t, senderUIN, clientID)
			if preReceiverUIN != sentinelReceiverUIN || preConversationID != sentinelConversationID || len(preEnvelope) == 0 || len(preEnvelopeHash) == 0 {
				t.Fatalf("pre-wipe sentinel check failed: receiver_uin=%d conversation_id=%q envelope=%q envelope_hash=%x -- seeding did not persist the expected sentinels, post-wipe checks would be meaningless", preReceiverUIN, preConversationID, preEnvelope, preEnvelopeHash)
			}

			wipe := func(uin int64) func() error {
				return func() error { return msgStore.DeleteUserMessages(ctx, uin) }
			}
			for j, err := range runReleasedTogether(wipe(uinA), wipe(uinB)) {
				if err != nil {
					t.Fatalf("concurrent wipe worker %d: %v", j, err)
				}
			}

			found, recipients, sanitized, state, gotExpiresAt := readGroupIngestRow(t, senderUIN, clientID)
			if !found {
				t.Fatal("row gone after exhaustion wipe of a no-expiry row")
			}
			if state != ingestRecipientErasedState || !sanitized || len(recipients) != 0 {
				t.Fatalf("no-expiry row not correctly terminalized: state=%q sanitized=%v recipients=%v", state, sanitized, recipients)
			}
			if !gotExpiresAt.IsZero() {
				t.Fatalf("expires_at = %v, want still unset -- terminalizing a no-expiry row must not introduce one", gotExpiresAt)
			}
			gotReceiverUIN, gotConversationID, gotEnvelope, gotEnvelopeHash := readIngestTombstoneFields(t, senderUIN, clientID)
			if gotReceiverUIN != 0 || gotConversationID != "" || len(gotEnvelope) != 0 || len(gotEnvelopeHash) != 0 {
				t.Fatalf("no-expiry row tombstone fields not actively cleared from their sentinels: receiver_uin=%d conversation_id=%q envelope=%q envelope_hash=%x", gotReceiverUIN, gotConversationID, gotEnvelope, gotEnvelopeHash)
			}

			// The write must have used the plain (non-"USING TTL") CAS
			// statement variant: proving this behaviorally against a real
			// TTL() read, not by inspecting the query string.
			var ttl int
			iter := session.Query(`SELECT TTL(recipient_set_sanitized) FROM message_ingest WHERE sender_uin = ? AND client_id = ?`, senderUIN, clientID).WithContext(ctx).Iter()
			iter.Scan(&ttl)
			if err := iter.Close(); err != nil {
				t.Fatalf("read TTL: %v", err)
			}
			if ttl != 0 {
				t.Fatalf("TTL(recipient_set_sanitized) = %d, want 0 (no expiry) -- the CAS write for a no-expiry row must not introduce a fresh TTL", ttl)
			}
			if got := countIngestErasureIndex(t, uinA); got != 0 {
				t.Fatalf("message_ingest_erasure_index for wiped uin A still has %d rows", got)
			}
			if got := countIngestErasureIndex(t, uinB); got != 0 {
				t.Fatalf("message_ingest_erasure_index for wiped uin B still has %d rows", got)
			}

			if err := msgStore.DeleteUserMessages(ctx, uinA); err != nil {
				t.Fatalf("repeated wipe of A: %v", err)
			}
			if err := msgStore.DeleteUserMessages(ctx, uinB); err != nil {
				t.Fatalf("repeated wipe of B: %v", err)
			}
			found, recipients, sanitized, state, gotExpiresAt = readGroupIngestRow(t, senderUIN, clientID)
			if !found || state != ingestRecipientErasedState || !sanitized || len(recipients) != 0 || !gotExpiresAt.IsZero() {
				t.Fatalf("repeated cleanup changed terminal state: found=%v state=%q sanitized=%v recipients=%v expiresAt=%v", found, state, sanitized, recipients, gotExpiresAt)
			}
		})

		t.Run("row already past its own expiry", func(t *testing.T) {
			uinA, uinB, _, senderUIN := freshUINs()
			clientID := "exhaustion-ingest-expired"
			groupID, err := gocql.RandomUUID()
			if err != nil {
				t.Fatal(err)
			}
			msgID, err := gocql.RandomUUID()
			if err != nil {
				t.Fatal(err)
			}
			createdAt := time.Now().UTC().Truncate(time.Millisecond)
			// The STORED expires_at is in the past, but the row carries a
			// long real CQL TTL so it stays queryable for this assertion --
			// deliberately exercising the "remaining <= 0 -> skip" branch
			// without racing real wall-clock expiry (mirrors the
			// already-established group_message_outbox equivalent in
			// panicwipe_acceptance_test.go).
			staleExpiresAt := createdAt.Add(-time.Hour)
			envelope := []byte("expired-exhaustion-envelope")
			hash := sha256.Sum256(envelope)
			if err := session.Query(`INSERT INTO message_ingest
				(sender_uin, client_id, message_kind, receiver_uin, conversation_id, group_id, crypto_epoch, recipient_uins, envelope, envelope_hash, message_id, created_at, expires_at, state, owner_token, lease_until)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL 3600`,
				senderUIN, clientID, "group", sentinelReceiverUIN, sentinelConversationID, groupID, int64(1), []int64{uinA, uinB},
				envelope, hash[:], msgID, createdAt, staleExpiresAt, "stored", msgID, createdAt,
			).WithContext(ctx).Exec(); err != nil {
				t.Fatalf("seed stale message_ingest: %v", err)
			}
			for _, indexUIN := range []int64{uinA, uinB, senderUIN} {
				if err := session.Query(`INSERT INTO message_ingest_erasure_index (uin, sender_uin, client_id) VALUES (?, ?, ?) USING TTL 3600`,
					indexUIN, senderUIN, clientID).WithContext(ctx).Exec(); err != nil {
					t.Fatalf("seed message_ingest_erasure_index (uin %d): %v", indexUIN, err)
				}
			}

			preReceiverUIN, preConversationID, preEnvelope, preEnvelopeHash := readIngestTombstoneFields(t, senderUIN, clientID)
			if preReceiverUIN != sentinelReceiverUIN || preConversationID != sentinelConversationID || len(preEnvelope) == 0 || len(preEnvelopeHash) == 0 {
				t.Fatalf("pre-wipe sentinel check failed: receiver_uin=%d conversation_id=%q envelope=%q envelope_hash=%x -- seeding did not persist the expected sentinels, post-wipe checks would be meaningless", preReceiverUIN, preConversationID, preEnvelope, preEnvelopeHash)
			}

			wipe := func(uin int64) func() error {
				return func() error { return msgStore.DeleteUserMessages(ctx, uin) }
			}
			for j, err := range runReleasedTogether(wipe(uinA), wipe(uinB)) {
				if err != nil {
					t.Fatalf("concurrent wipe of an already-expired row worker %d: %v", j, err)
				}
			}

			// Left exactly as seeded: skip, don't mutate. Both wiped uins
			// and the sentinel receiver_uin/conversation_id/ciphertext are
			// still allowed to be present here -- the row is about to
			// vanish via its own already-past expiry, so mutating it (and
			// risking a fresh/permanent TTL landing on it) is unnecessary
			// and risky. This must never reach the exhaustion/terminalize
			// CAS branch at all.
			found, recipients, sanitized, state, gotExpiresAt := readGroupIngestRow(t, senderUIN, clientID)
			if !found {
				t.Fatal("already-expired row was deleted -- must be left untouched, not removed")
			}
			if state != "stored" {
				t.Fatalf("state = %q, want unchanged %q -- an expired row must never be terminalized", state, "stored")
			}
			if sanitized {
				t.Fatal("recipient_set_sanitized = true on an already-expired row that should have been left untouched")
			}
			if len(recipients) != 2 {
				t.Fatalf("recipient_uins = %v, want both original recipients untouched", recipients)
			}
			if !gotExpiresAt.Equal(staleExpiresAt) {
				t.Fatalf("expires_at = %v, want unchanged stale value %v", gotExpiresAt, staleExpiresAt)
			}
			postReceiverUIN, postConversationID, postEnvelope, postEnvelopeHash := readIngestTombstoneFields(t, senderUIN, clientID)
			if postReceiverUIN != sentinelReceiverUIN || postConversationID != sentinelConversationID || string(postEnvelope) != string(envelope) || string(postEnvelopeHash) != string(hash[:]) {
				t.Fatalf("already-expired row was mutated: receiver_uin=%d conversation_id=%q envelope=%q envelope_hash=%x, want the original sentinels/ciphertext untouched", postReceiverUIN, postConversationID, postEnvelope, postEnvelopeHash)
			}

			// A retried wipe on the same still-expired row is equally safe.
			if err := msgStore.DeleteUserMessages(ctx, uinA); err != nil {
				t.Fatalf("repeated wipe of an already-expired row: %v", err)
			}
			found, recipients, _, state, _ = readGroupIngestRow(t, senderUIN, clientID)
			if !found || state != "stored" || len(recipients) != 2 {
				t.Fatalf("repeated wipe of an already-expired row changed it: found=%v state=%q recipients=%v", found, state, recipients)
			}
		})
	})

	t.Run("group_message_outbox: concurrent wipe of the last two recipients deletes the row", func(t *testing.T) {
		t.Run("row has time remaining", func(t *testing.T) {
			uinA, uinB, _, senderUIN := freshUINs()
			bucket, createdAt, msgID := seedGroupOutboxRow(t, senderUIN, []int64{uinA, uinB}, "exhaustion-ttl", 3600)

			wipe := func(uin int64) func() error {
				return func() error { return msgStore.DeleteUserGroupMessages(ctx, uin) }
			}
			for j, err := range runReleasedTogether(wipe(uinA), wipe(uinB)) {
				if err != nil {
					t.Fatalf("concurrent wipe worker %d: %v", j, err)
				}
			}

			if found, recipients := readGroupOutboxRow(t, bucket, createdAt, msgID); found {
				t.Fatalf("group_message_outbox row still exists after both recipients wiped, recipients=%v -- an exhausted row must be deleted", recipients)
			}
			if got := countOutboxErasureIndex(t, uinA); got != 0 {
				t.Fatalf("group_message_outbox_erasure_index for wiped uin A still has %d rows", got)
			}
			if got := countOutboxErasureIndex(t, uinB); got != 0 {
				t.Fatalf("group_message_outbox_erasure_index for wiped uin B still has %d rows", got)
			}

			// Repeat cleanup safely: the row is already gone, both calls
			// must be no-ops, not errors.
			if err := msgStore.DeleteUserGroupMessages(ctx, uinA); err != nil {
				t.Fatalf("repeated wipe of A after deletion: %v", err)
			}
			if err := msgStore.DeleteUserGroupMessages(ctx, uinB); err != nil {
				t.Fatalf("repeated wipe of B after deletion: %v", err)
			}
			if found, _ := readGroupOutboxRow(t, bucket, createdAt, msgID); found {
				t.Fatal("row resurrected by a repeated cleanup call")
			}
		})

		t.Run("row has no expiry configured", func(t *testing.T) {
			uinA, uinB, _, senderUIN := freshUINs()
			groupID, err := gocql.RandomUUID()
			if err != nil {
				t.Fatal(err)
			}
			msgID, err := gocql.RandomUUID()
			if err != nil {
				t.Fatal(err)
			}
			createdAt := time.Now().UTC().Truncate(time.Millisecond)
			bucket := int8(msgID[0] & 15)
			// No "USING TTL" clause and no expires_at value: a permanent
			// outbox row. Schema permits this: expires_at is a plain
			// nullable TIMESTAMP.
			if err := session.Query(`INSERT INTO group_message_outbox
				(bucket, created_at, message_id, group_id, sender_uin, client_id, crypto_epoch, recipient_uins, envelope, envelope_hash, state)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				bucket, createdAt, msgID, groupID, senderUIN, "outbox-no-ttl", 1,
				[]int64{uinA, uinB}, []byte("env"), []byte("hash12345678901234567890123456789012"), "pending",
			).WithContext(ctx).Exec(); err != nil {
				t.Fatalf("seed no-TTL group_message_outbox: %v", err)
			}
			for _, indexUIN := range []int64{uinA, uinB} {
				if err := session.Query(`INSERT INTO group_message_outbox_erasure_index (uin, bucket, created_at, message_id, role) VALUES (?, ?, ?, ?, ?) USING TTL 3600`,
					indexUIN, bucket, createdAt, msgID, "recipient").WithContext(ctx).Exec(); err != nil {
					t.Fatalf("seed group_message_outbox_erasure_index (uin %d): %v", indexUIN, err)
				}
			}

			wipe := func(uin int64) func() error {
				return func() error { return msgStore.DeleteUserGroupMessages(ctx, uin) }
			}
			for j, err := range runReleasedTogether(wipe(uinA), wipe(uinB)) {
				if err != nil {
					t.Fatalf("concurrent wipe worker %d: %v", j, err)
				}
			}

			if found, recipients := readGroupOutboxRow(t, bucket, createdAt, msgID); found {
				t.Fatalf("no-expiry group_message_outbox row still exists after both recipients wiped, recipients=%v", recipients)
			}
			if got := countOutboxErasureIndex(t, uinA); got != 0 {
				t.Fatalf("group_message_outbox_erasure_index for wiped uin A still has %d rows", got)
			}
			if got := countOutboxErasureIndex(t, uinB); got != 0 {
				t.Fatalf("group_message_outbox_erasure_index for wiped uin B still has %d rows", got)
			}
		})

		t.Run("row already past its own expiry", func(t *testing.T) {
			uinA, uinB, _, senderUIN := freshUINs()
			groupID, err := gocql.RandomUUID()
			if err != nil {
				t.Fatal(err)
			}
			msgID, err := gocql.RandomUUID()
			if err != nil {
				t.Fatal(err)
			}
			createdAt := time.Now().UTC().Truncate(time.Millisecond)
			bucket := int8(msgID[0] & 15)
			staleExpiresAt := createdAt.Add(-time.Hour)
			if err := session.Query(`INSERT INTO group_message_outbox
				(bucket, created_at, message_id, group_id, sender_uin, client_id, crypto_epoch, recipient_uins, envelope, envelope_hash, state, expires_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL 3600`,
				bucket, createdAt, msgID, groupID, senderUIN, "outbox-expired", 1,
				[]int64{uinA, uinB}, []byte("env"), []byte("hash12345678901234567890123456789012"), "pending", staleExpiresAt,
			).WithContext(ctx).Exec(); err != nil {
				t.Fatalf("seed stale group_message_outbox: %v", err)
			}
			for _, indexUIN := range []int64{uinA, uinB} {
				if err := session.Query(`INSERT INTO group_message_outbox_erasure_index (uin, bucket, created_at, message_id, role) VALUES (?, ?, ?, ?, ?) USING TTL 3600`,
					indexUIN, bucket, createdAt, msgID, "recipient").WithContext(ctx).Exec(); err != nil {
					t.Fatalf("seed group_message_outbox_erasure_index (uin %d): %v", indexUIN, err)
				}
			}

			wipe := func(uin int64) func() error {
				return func() error { return msgStore.DeleteUserGroupMessages(ctx, uin) }
			}
			for j, err := range runReleasedTogether(wipe(uinA), wipe(uinB)) {
				if err != nil {
					t.Fatalf("concurrent wipe of an already-expired row worker %d: %v", j, err)
				}
			}

			// Left exactly as seeded: an already-expired row must never
			// reach the exhaustion/DELETE branch, even when both of its
			// recipients are wiped at once.
			found, recipients := readGroupOutboxRow(t, bucket, createdAt, msgID)
			if !found {
				t.Fatal("already-expired group_message_outbox row was deleted -- must be left untouched, not removed by the exhaustion path")
			}
			if len(recipients) != 2 {
				t.Fatalf("recipient_uins = %v, want both original recipients untouched", recipients)
			}

			if err := msgStore.DeleteUserGroupMessages(ctx, uinA); err != nil {
				t.Fatalf("repeated wipe of an already-expired row: %v", err)
			}
			found, recipients = readGroupOutboxRow(t, bucket, createdAt, msgID)
			if !found || len(recipients) != 2 {
				t.Fatalf("repeated wipe of an already-expired row changed it: found=%v recipients=%v", found, recipients)
			}
		})
	})
}
