package handlers

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSenderKeyInboxRejectsCiphertextLargerThan16KiB(t *testing.T) {
	db := &groupFakeDB{}
	ciphertext := base64.RawURLEncoding.EncodeToString(make([]byte, 16*1024+1))
	rr := httptest.NewRecorder()
	body := `{"recipient_uin":200,"epoch":4,"distribution_id":"d1","ciphertext":"` + ciphertext + `","msg_type":"signal_message"}`
	NewPutSenderKeyDistributionHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodPost, "/api/groups/"+behaviorGroupID+"/sender-key-distributions", body, 100))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(db.calls) != 0 {
		t.Fatalf("oversized ciphertext reached database: %#v", db.calls)
	}
}

func TestSenderKeyInboxPutBindsAuthenticatedSenderRecipientAndCurrentEpoch(t *testing.T) {
	db := &groupFakeDB{rowQueue: [][]any{{true, true}}}
	rr := httptest.NewRecorder()
	NewPutSenderKeyDistributionHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodPost, "/api/groups/"+behaviorGroupID+"/sender-key-distributions", `{"recipient_uin":200,"epoch":4,"distribution_id":"d1","ciphertext":"b3BhcXVl","msg_type":"signal_message"}`, 100))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	q := strings.ToUpper(db.calls[0].sql)
	if !strings.Contains(q, "GROUP_MEMBERS") || !strings.Contains(q, "CRYPTO_EPOCH") || db.calls[0].args[1] != int64(100) || db.calls[0].args[2] != int64(200) {
		t.Fatalf("query/args not fail-closed: %s %#v", q, db.calls[0].args)
	}
	if !strings.Contains(q, "DISTRIBUTION_ID) DO NOTHING") {
		t.Fatal("same-epoch distribution ids are not independently retained")
	}
	if !strings.Contains(q, "ROW_NUMBER() OVER") || !strings.Contains(q, "RETIRED_AT < NOW()-INTERVAL '24 HOURS'") {
		t.Fatalf("bounded/expired cleanup missing: %s", q)
	}
	if !strings.Contains(q, "FOR UPDATE") {
		t.Fatalf("concurrent distribution cleanup is not serialized: %s", q)
	}
}

func TestSenderKeyInboxGetRequiresCurrentRecipientMembershipAndEpoch(t *testing.T) {
	db := &groupFakeDB{rowQueue: [][]any{{int64(4)}}, rowsQueue: [][][]any{{{int64(4), int64(100), "b3BhcXVl", "signal_message", "d1", (*time.Time)(nil)}}}}
	rr := httptest.NewRecorder()
	NewGetSenderKeyDistributionsHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodGet, "/api/groups/"+behaviorGroupID+"/sender-key-distributions", "", 200))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"sender_uin":100`) {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if db.calls[0].args[1] != int64(200) {
		t.Fatalf("membership not bound to actor: %#v", db.calls[0].args)
	}
	if !strings.Contains(strings.ToUpper(db.calls[1].sql), "RETIRED_AT > NOW()-INTERVAL '24 HOURS'") {
		t.Fatal("bounded decrypt-only grace missing")
	}
	query := strings.ToUpper(db.calls[1].sql)
	if !strings.Contains(query, "ROW_NUMBER() OVER (PARTITION BY SENDER_UIN") || !strings.Contains(query, "SENDER_RANK") {
		t.Fatalf("per-sender fair selection missing: %s", query)
	}
	if !strings.Contains(query, "OFFSET $5") {
		t.Fatalf("bounded paging missing: %s", query)
	}
}

func TestSenderKeyInboxResponseStopsBeforeTotalCiphertextCap(t *testing.T) {
	large := strings.Repeat("A", maxSenderKeyInboxResponseBytes/2+1)
	db := &groupFakeDB{
		rowQueue: [][]any{{int64(4)}},
		rowsQueue: [][][]any{{
			{int64(4), int64(100), large, "signal_message", "d1", (*time.Time)(nil)},
			{int64(4), int64(200), large, "signal_message", "d2", (*time.Time)(nil)},
		}},
	}
	rr := httptest.NewRecorder()
	NewGetSenderKeyDistributionsHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodGet, "/api/groups/"+behaviorGroupID+"/sender-key-distributions?page=0", "", 200))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"distribution_id":"d2"`) {
		t.Fatalf("response exceeded ciphertext budget: bytes=%d", rr.Body.Len())
	}
}
