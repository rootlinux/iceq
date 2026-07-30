package store

import (
	"os"
	"strings"
	"testing"
)

// paginationPage is the exact has-more decision at the core of the history
// pagination fix: fetch up to limit+1 rows, return at most limit, and prove
// "more data exists" only when the extra row actually showed up. These
// cases mirror the required test matrix directly.
func TestPaginationPage(t *testing.T) {
	cases := []struct {
		name        string
		fetched     int
		limit       int
		wantKeep    int
		wantHasMore bool
	}{
		{"zero rows", 0, 20, 0, false},
		{"fewer than limit", 5, 20, 5, false},
		{"exactly limit, no additional row", 20, 20, 20, false},
		{"limit+1 rows", 21, 20, 20, true},
		{"limit of 1, two fetched", 2, 1, 1, true},
		{"max limit (50), 51 fetched", 51, 50, 50, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keep, hasMore := paginationPage(tc.fetched, tc.limit)
			if keep != tc.wantKeep || hasMore != tc.wantHasMore {
				t.Fatalf("paginationPage(%d, %d) = (%d, %v), want (%d, %v)", tc.fetched, tc.limit, keep, hasMore, tc.wantKeep, tc.wantHasMore)
			}
		})
	}
}

// TestHistoryQueriesFetchLimitPlusOne is a source-shape contract test,
// matching the existing convention in this package for asserting Scylla
// query construction without a live cluster (see
// group_crypto_epoch_contract_test.go). It proves GetHistory and
// GetGroupHistory actually request one row beyond the caller's limit --
// the mechanism paginationPage's exactness depends on.
func TestHistoryQueriesFetchLimitPlusOne(t *testing.T) {
	src, err := os.ReadFile("messagestore.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{
		"Query(q, req.ConversationID, before, limit+1)",
		"Query(q, req.GroupID, before, limit+1)",
		"keep, hasMore := paginationPage(len(rows), limit)",
	} {
		if strings.Count(s, want) == 0 {
			t.Errorf("messagestore.go missing %q", want)
		}
	}
	// keep, hasMore := paginationPage(...) must appear exactly twice: once
	// for GetHistory, once for GetGroupHistory. A single occurrence would
	// mean one of the two paths reverted to the old inferred-hasMore logic.
	if n := strings.Count(s, "keep, hasMore := paginationPage(len(rows), limit)"); n != 2 {
		t.Errorf("expected paginationPage to be wired into both GetHistory and GetGroupHistory, found %d call sites", n)
	}
}
