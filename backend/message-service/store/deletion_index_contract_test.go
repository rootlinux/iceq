package store

import (
	"os"
	"strings"
	"testing"
)

func TestMessageWritesMaintainDeletionIndexesWithoutClusterScan(t *testing.T) {
	src, err := os.ReadFile("messagestore.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{"message_deletion_index", "group_message_deletion_index", "req.SenderUIN", "req.ReceiverUIN != req.SenderUIN"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing deletion-index contract %q", want)
		}
	}
	if strings.Contains(strings.ToUpper(s), "ALLOW FILTERING") {
		t.Fatal("message store must not use ALLOW FILTERING")
	}
}
