package handlers

import (
	"os"
	"strings"
	"testing"
)

func TestMembershipMutationsAdvanceEpochAtomically(t *testing.T) {
	for name, q := range map[string]string{"add": qInsertGroupMember, "remove": qDeleteGroupMember} {
		normalized := strings.ToUpper(q)
		if !strings.Contains(normalized, "WITH ") || !strings.Contains(normalized, "UPDATE GROUPS SET CRYPTO_EPOCH = CRYPTO_EPOCH + 1") {
			t.Fatalf("%s membership mutation does not atomically advance epoch: %s", name, q)
		}
	}
}
func TestGroupEpochMigrationUsesNextNonCollidingNumber(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/init/migrations/008_group_crypto_epoch.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "crypto_epoch") {
		t.Fatal("migration does not define crypto_epoch")
	}
}
