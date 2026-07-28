package handlers

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestScyllaWipeUsesUINPartitionedIndexesWithoutAllowFiltering(t *testing.T) {
	src, err := os.ReadFile("scyllastore.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{
		"message_deletion_index WHERE uin = ?",
		"group_message_deletion_index WHERE uin = ?",
		"DELETE FROM messages WHERE conversation_id = ? AND created_at = ? AND id = ?",
		"DELETE FROM group_messages WHERE group_id = ? AND created_at = ? AND id = ?",
		// Erasure-indexed tables must delete via indexes, not scans.
		"message_ingest_erasure_index WHERE uin = ?",
		"message_outbox_erasure_index WHERE uin = ?",
		"group_message_outbox_erasure_index WHERE uin = ?",
		"DELETE FROM message_ingest WHERE sender_uin = ? AND client_id = ?",
		"DELETE FROM message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?",
		"DELETE FROM group_message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing indexed wipe contract %q", want)
		}
	}
	if strings.Contains(strings.ToUpper(s), "ALLOW FILTERING") {
		t.Fatal("panic wipe must not scan the cluster")
	}
}

// TestScyllaGroupRecipientSanitizationPreservesTTLAndUsesNonIdentifyingMarker
// locks in the shape of the group-recipient wipe path: every write that
// touches a still-live message_ingest row must carry an explicit USING TTL
// (an UPDATE without one makes the touched cells non-expiring -- see
// remainingIngestTTLSeconds), must be a compare-and-set conditioned on the
// exact recipient_uins value just read (not a bare IF EXISTS, which only
// guards row existence and allowed a lost-update race between two
// concurrent wipe workers -- see maxRecipientSanitizeCASAttempts and
// TestAcceptanceGroupRecipientConcurrentWipeNeverResurrects), and must
// record sanitization only via the non-identifying recipient_set_sanitized
// marker.
func TestScyllaGroupRecipientSanitizationPreservesTTLAndUsesNonIdentifyingMarker(t *testing.T) {
	src, err := os.ReadFile("scyllastore.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)

	for _, want := range []string{
		// Partial sanitize: recipients remain. Both TTL and non-TTL (durable
		// row) CAS variants, each conditioned on the recipient_uins value
		// just read -- this is sanitizeGroupIngestRecipients, called only
		// from the group branch (the direct branch has exactly one
		// receiver_uin and cannot race, so it keeps terminalizeIngestReceipt's
		// plain IF EXISTS -- see the sibling function's own doc comment).
		"UPDATE message_ingest SET recipient_uins = ?, recipient_set_sanitized = ? WHERE sender_uin = ? AND client_id = ? IF recipient_uins = ?",
		"UPDATE message_ingest USING TTL ? SET recipient_uins = ?, recipient_set_sanitized = ? WHERE sender_uin = ? AND client_id = ? IF recipient_uins = ?",
		// Terminalize (group exhausted), same CAS conditioning, both variants.
		"UPDATE message_ingest SET state = ?, receiver_uin = ?, conversation_id = ?, recipient_uins = ?, envelope = ?, envelope_hash = ?, recipient_set_sanitized = ? WHERE sender_uin = ? AND client_id = ? IF recipient_uins = ?",
		"UPDATE message_ingest USING TTL ? SET state = ?, receiver_uin = ?, conversation_id = ?, recipient_uins = ?, envelope = ?, envelope_hash = ?, recipient_set_sanitized = ? WHERE sender_uin = ? AND client_id = ? IF recipient_uins = ?",
		// The marker itself, and the shared terminal state contract with
		// message-service/store's IngestRecipientErased.
		"recipient_set_sanitized",
		`ingestRecipientErasedState = "recipient_erased"`,
		// The CAS retry bound and its context-cancellation guard.
		"maxRecipientSanitizeCASAttempts",
		"ctx.Err()",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing sanitization contract %q", want)
		}
	}

	// The wiped uin must never be written into a provenance/tracking field.
	// This is necessarily a denylist of names we know NOT to introduce --
	// it cannot prove the absence of every possible leak, but catches the
	// specific shapes the design explicitly ruled out.
	for _, banned := range []string{
		"wipe_removed_recipient",
		"erased_by_uin",
		"erased_recipient_uin",
		"removed_uin",
		"wiped_uin_history",
	} {
		if strings.Contains(strings.ToLower(s), strings.ToLower(banned)) {
			t.Fatalf("scyllastore.go must not track the wiped uin via a provenance field %q", banned)
		}
	}
}

// TestScyllaGroupOutboxRecipientRemovalPreservesTTL locks in the fix for a
// TTL-loss defect found while verifying Task #12: the pre-existing
// recipient-removal UPDATE on group_message_outbox did not carry USING TTL,
// which silently turns an expiring row permanent (a bare UPDATE writes its
// touched cells with no TTL; group_message_outbox has no table-level
// default_time_to_live). The fix reads expires_at alongside recipient_uins
// and threads the remaining TTL through explicitly.
func TestScyllaGroupOutboxRecipientRemovalPreservesTTL(t *testing.T) {
	src, err := os.ReadFile("scyllastore.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)

	for _, want := range []string{
		"SELECT recipient_uins, expires_at FROM group_message_outbox WHERE bucket = ? AND created_at = ? AND message_id = ?",
		// CAS-conditioned on the exact recipient_uins value just read, not a
		// bare IF EXISTS -- see TestAcceptanceGroupRecipientConcurrentWipeNeverResurrects.
		"UPDATE group_message_outbox USING TTL ? SET recipient_uins = ? WHERE bucket = ? AND created_at = ? AND message_id = ? IF recipient_uins = ?",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing group outbox TTL-preservation contract %q", want)
		}
	}

	if strings.Contains(s, "recipient_uins = ? WHERE bucket = ? AND created_at = ? AND message_id = ? IF EXISTS") {
		t.Fatal("group_message_outbox recipient_uins UPDATE must be CAS-conditioned on the read value (IF recipient_uins = ?), not a bare IF EXISTS")
	}
}

// TestRemainingIngestTTLSecondsHandlesZeroAndPastExpiry proves the pure TTL
// helper both the message_ingest and group_message_outbox sanitization paths
// rely on can never authorize resurrecting an expired or
// permanently-durable row with a fresh bounded TTL, and never under-reports
// a genuinely future expiry. This is the deterministic, Scylla-free half of
// "TTL<=0 cannot create a permanent row" -- the live-Scylla half is proven
// by the acceptance test.
func TestRemainingIngestTTLSecondsHandlesZeroAndPastExpiry(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

	if got := remainingIngestTTLSeconds(time.Time{}, now); got != 0 {
		t.Fatalf("zero expiresAt (durable/non-expiring row) = %d, want 0", got)
	}
	if got := remainingIngestTTLSeconds(now.Add(-time.Hour), now); got != 0 {
		t.Fatalf("past expiresAt = %d, want 0 -- must never resurrect an already-expired row with a fresh TTL", got)
	}
	if got := remainingIngestTTLSeconds(now, now); got != 0 {
		t.Fatalf("expiresAt exactly now = %d, want 0", got)
	}
	if got := remainingIngestTTLSeconds(now.Add(90*time.Second), now); got != 90 {
		t.Fatalf("expiresAt 90s in the future = %d, want 90", got)
	}
	if got := remainingIngestTTLSeconds(now.Add(90500*time.Millisecond), now); got != 91 {
		t.Fatalf("sub-second remainder must round up (ceil), got %d, want 91", got)
	}
}
