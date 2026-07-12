package handlers

import (
	"os"
	"strings"
	"testing"
)

func TestScyllaWipeUsesUINPartitionedIndexesWithoutAllowFiltering(t *testing.T) {
	src, err := os.ReadFile("scyllastore.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{"message_deletion_index WHERE uin = ?", "group_message_deletion_index WHERE uin = ?", "DELETE FROM messages WHERE conversation_id = ? AND created_at = ? AND id = ?", "DELETE FROM group_messages WHERE group_id = ? AND created_at = ? AND id = ?"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing indexed wipe contract %q", want)
		}
	}
	if strings.Contains(strings.ToUpper(s), "ALLOW FILTERING") {
		t.Fatal("panic wipe must not scan the cluster")
	}
}
