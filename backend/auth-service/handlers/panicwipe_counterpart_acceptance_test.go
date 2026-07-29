//go:build integration
// +build integration

// Package handlers — acceptance coverage for the DM message_deletion_index
// counterpart-orphan fix (dmCounterpartUIN / DeleteUserMessages in
// scyllastore.go). Gated by the same ICEQ_ACCEPTANCE=1 opt-in as the rest of
// this file's disposable five-storage acceptance suite; like
// TestAcceptanceGroupRecipientWipeTTLBehavior, these tests only need a real
// Scylla connection, so that is the only storage layer they connect to.
//
// message_deletion_index holds one pointer row per DM participant, both
// pointing at the same messages row (see messagestore.go's SaveMessage and
// durable_ingest_scylla.go's WriteDirect). Before this fix,
// ScyllaMessageStore.DeleteUserMessages deleted the shared messages row
// using only the wiped user's own index entry, leaving the counterpart's
// mirror entry dangling: a TTL-bounded row on the SURVIVING party's own
// partition whose conversation_id clustering key embeds the wiped UIN as
// plaintext. These tests seed real dm:<min>:<max> conversations exactly as
// the production write path does and prove the counterpart's mirror row is
// gone immediately, not just eventually via TTL.
package handlers

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gocql/gocql"
)

// seedDMMessage inserts one messages row plus both participants'
// message_deletion_index entries, matching exactly what
// durable_ingest_scylla.go's WriteDirect (and messagestore.go's SaveMessage)
// write for a real direct message — no TTL, so the row does not
// self-expire during the test.
func seedDMMessage(t *testing.T, session *gocql.Session, convID string, senderUIN, receiverUIN int64) (time.Time, gocql.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	createdAt := time.Now().UTC().Truncate(time.Millisecond)
	id, err := gocql.RandomUUID()
	if err != nil {
		t.Fatalf("generate message id: %v", err)
	}
	// A fresh (createdAt, id) pair per call keeps concurrently seeded
	// messages from colliding on the same clustering key.
	time.Sleep(time.Millisecond)

	if err := session.Query(`INSERT INTO messages (conversation_id, created_at, id, sender_uin, receiver_uin, ciphertext, msg_type, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, convID, createdAt, id, senderUIN, receiverUIN, []byte("ciphertext"), "signal_message", "").WithContext(ctx).Exec(); err != nil {
		t.Fatalf("seed messages row: %v", err)
	}
	if err := session.Query(`INSERT INTO message_deletion_index (uin, conversation_id, created_at, id) VALUES (?, ?, ?, ?)`,
		senderUIN, convID, createdAt, id).WithContext(ctx).Exec(); err != nil {
		t.Fatalf("seed sender deletion index: %v", err)
	}
	if receiverUIN != senderUIN {
		if err := session.Query(`INSERT INTO message_deletion_index (uin, conversation_id, created_at, id) VALUES (?, ?, ?, ?)`,
			receiverUIN, convID, createdAt, id).WithContext(ctx).Exec(); err != nil {
			t.Fatalf("seed receiver deletion index: %v", err)
		}
	}
	return createdAt, id
}

func messagesRowExists(t *testing.T, session *gocql.Session, convID string, createdAt time.Time, id gocql.UUID) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var count int
	iter := session.Query(`SELECT COUNT(*) FROM messages WHERE conversation_id = ? AND created_at = ? AND id = ?`, convID, createdAt, id).WithContext(ctx).Iter()
	iter.Scan(&count)
	if err := iter.Close(); err != nil {
		t.Fatalf("messages iter close: %v", err)
	}
	return count != 0
}

func deletionIndexRowExists(t *testing.T, session *gocql.Session, uin int64, convID string, createdAt time.Time, id gocql.UUID) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var count int
	iter := session.Query(`SELECT COUNT(*) FROM message_deletion_index WHERE uin = ? AND conversation_id = ? AND created_at = ? AND id = ?`,
		uin, convID, createdAt, id).WithContext(ctx).Iter()
	iter.Scan(&count)
	if err := iter.Close(); err != nil {
		t.Fatalf("message_deletion_index iter close: %v", err)
	}
	return count != 0
}

// newAcceptanceScyllaStore connects to the disposable acceptance Scylla
// instance and returns a ready ScyllaMessageStore. Mirrors
// TestAcceptanceGroupRecipientWipeTTLBehavior's bootstrap exactly -- these
// counterpart-cleanup scenarios do not need Postgres, Redis, NATS, or MinIO.
func newAcceptanceScyllaStore(t *testing.T) *ScyllaMessageStore {
	t.Helper()
	requireAcceptanceEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
	t.Cleanup(session.Close)
	applyScyllaSchema(t, session)

	store, err := NewScyllaMessageStore(session)
	if err != nil {
		t.Fatalf("create Scylla store: %v", err)
	}
	return store
}

// TestAcceptanceDMCounterpartIndexCleanedBothDirections covers scenarios 1-3
// of the cross-partition cleanup spec: A sends to B then A wipes, B sends to
// A then A wipes, and multiple messages in one conversation -- all in one
// pass since dmCounterpartUIN doesn't care which side of a message a wiped
// user was on. Also proves an UNRELATED conversation (B talking to a third
// party) is left completely alone.
func TestAcceptanceDMCounterpartIndexCleanedBothDirections(t *testing.T) {
	store := newAcceptanceScyllaStore(t)
	session := store.session

	const (
		userA        = int64(920001) // gets wiped
		userB        = int64(920002) // survives, must lose the orphaned mirror
		unrelatedC   = int64(920003) // survives, completely uninvolved with A
	)
	convAB := "dm:920001:920002"
	convBC := "dm:920002:920003"

	// Scenario 1: A sends to B.
	createdAt1, id1 := seedDMMessage(t, session, convAB, userA, userB)
	// Scenario 2: B sends to A (opposite direction, same conversation).
	createdAt2, id2 := seedDMMessage(t, session, convAB, userB, userA)
	// Scenario 3: another message from A to B (multiple messages).
	createdAt3, id3 := seedDMMessage(t, session, convAB, userA, userB)
	// Unrelated conversation: B talking to someone who is not A.
	createdAtBC, idBC := seedDMMessage(t, session, convBC, userB, unrelatedC)

	for _, seeded := range []struct {
		label     string
		createdAt time.Time
		id        gocql.UUID
	}{
		{"msg1 (A->B)", createdAt1, id1},
		{"msg2 (B->A)", createdAt2, id2},
		{"msg3 (A->B)", createdAt3, id3},
	} {
		if !messagesRowExists(t, session, convAB, seeded.createdAt, seeded.id) {
			t.Fatalf("precondition failed: %s messages row missing before wipe", seeded.label)
		}
		if !deletionIndexRowExists(t, session, userA, convAB, seeded.createdAt, seeded.id) {
			t.Fatalf("precondition failed: %s userA deletion index missing before wipe", seeded.label)
		}
		if !deletionIndexRowExists(t, session, userB, convAB, seeded.createdAt, seeded.id) {
			t.Fatalf("precondition failed: %s userB deletion index missing before wipe", seeded.label)
		}
	}

	if err := store.DeleteUserMessages(context.Background(), userA); err != nil {
		t.Fatalf("DeleteUserMessages(userA): %v", err)
	}

	for _, seeded := range []struct {
		label     string
		createdAt time.Time
		id        gocql.UUID
	}{
		{"msg1 (A->B)", createdAt1, id1},
		{"msg2 (B->A)", createdAt2, id2},
		{"msg3 (A->B)", createdAt3, id3},
	} {
		if messagesRowExists(t, session, convAB, seeded.createdAt, seeded.id) {
			t.Errorf("%s: messages ciphertext row still exists after A's wipe", seeded.label)
		}
		if deletionIndexRowExists(t, session, userA, convAB, seeded.createdAt, seeded.id) {
			t.Errorf("%s: wiped user A's own deletion index row still exists", seeded.label)
		}
		// The counterpart-orphan fix: B never wiped, but B's mirror row
		// pointing at this now-deleted message must be gone too.
		if deletionIndexRowExists(t, session, userB, convAB, seeded.createdAt, seeded.id) {
			t.Errorf("%s: counterpart B's deletion index row was left orphaned (contains wiped UIN %d in its conversation_id) — the counterpart-orphan fix did not run", seeded.label, userA)
		}
	}

	// Unrelated B<->C conversation must be completely untouched.
	if !messagesRowExists(t, session, convBC, createdAtBC, idBC) {
		t.Error("unrelated B<->C messages row was deleted by A's wipe")
	}
	if !deletionIndexRowExists(t, session, userB, convBC, createdAtBC, idBC) {
		t.Error("unrelated B<->C deletion index (B's side) was deleted by A's wipe")
	}
	if !deletionIndexRowExists(t, session, unrelatedC, convBC, createdAtBC, idBC) {
		t.Error("unrelated B<->C deletion index (C's side) was deleted by A's wipe")
	}
}

// TestAcceptanceDMCounterpartCleanupIsIdempotentUnderRepeatedAndConcurrentWipes
// covers scenarios 6 and 7: concurrent wipes of both DM participants, and
// repeated cleanup after a simulated partial-failure retry. Neither must
// error, duplicate work, or resurrect a deleted row.
func TestAcceptanceDMCounterpartCleanupIsIdempotentUnderRepeatedAndConcurrentWipes(t *testing.T) {
	store := newAcceptanceScyllaStore(t)
	session := store.session

	t.Run("concurrent wipe of both participants", func(t *testing.T) {
		const (
			userA = int64(920011)
			userB = int64(920012)
		)
		convID := "dm:920011:920012"
		createdAt, id := seedDMMessage(t, session, convID, userA, userB)

		var wg sync.WaitGroup
		errs := make(chan error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs <- store.DeleteUserMessages(context.Background(), userA)
		}()
		go func() {
			defer wg.Done()
			errs <- store.DeleteUserMessages(context.Background(), userB)
		}()
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("concurrent DeleteUserMessages returned an error: %v", err)
			}
		}

		if messagesRowExists(t, session, convID, createdAt, id) {
			t.Error("messages row survives concurrent wipe of both participants")
		}
		if deletionIndexRowExists(t, session, userA, convID, createdAt, id) {
			t.Error("userA deletion index row survives concurrent wipe")
		}
		if deletionIndexRowExists(t, session, userB, convID, createdAt, id) {
			t.Error("userB deletion index row survives concurrent wipe")
		}
	})

	t.Run("repeated cleanup after simulated partial-failure retry", func(t *testing.T) {
		const (
			userA = int64(920013)
			userB = int64(920014)
		)
		convID := "dm:920013:920014"
		createdAt, id := seedDMMessage(t, session, convID, userA, userB)

		if err := store.DeleteUserMessages(context.Background(), userA); err != nil {
			t.Fatalf("first DeleteUserMessages call: %v", err)
		}
		// Simulate the wipe job retrying after an unrelated phase (NATS,
		// MinIO, ...) failed and the whole job was rescheduled: the Scylla
		// phase runs again against already-cleaned state.
		if err := store.DeleteUserMessages(context.Background(), userA); err != nil {
			t.Fatalf("repeated DeleteUserMessages call must be a no-op, not an error: %v", err)
		}

		if messagesRowExists(t, session, convID, createdAt, id) {
			t.Error("messages row exists after repeated cleanup")
		}
		if deletionIndexRowExists(t, session, userA, convID, createdAt, id) {
			t.Error("userA deletion index row exists after repeated cleanup")
		}
		if deletionIndexRowExists(t, session, userB, convID, createdAt, id) {
			t.Error("userB (counterpart) deletion index row exists after repeated cleanup")
		}
	})
}
