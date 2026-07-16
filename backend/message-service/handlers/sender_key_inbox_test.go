package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSenderKeyInboxPutBindsAuthenticatedSenderRecipientAndCurrentEpoch(t *testing.T) {
	db := &groupFakeDB{}
	rr := httptest.NewRecorder()
	NewPutSenderKeyDistributionHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodPost, "/api/groups/"+behaviorGroupID+"/sender-key-distributions", `{"recipient_uin":200,"epoch":4,"distribution_id":"d1","ciphertext":"b3BhcXVl","msg_type":"signal_message"}`, 100))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	q := strings.ToUpper(db.calls[0].sql)
	if !strings.Contains(q, "GROUP_MEMBERS") || !strings.Contains(q, "CRYPTO_EPOCH") || db.calls[0].args[1] != int64(100) || db.calls[0].args[2] != int64(200) {
		t.Fatalf("query/args not fail-closed: %s %#v", q, db.calls[0].args)
	}
}

func TestSenderKeyInboxGetRequiresCurrentRecipientMembershipAndEpoch(t *testing.T) {
	db := &groupFakeDB{rowQueue: [][]any{{int64(4)}}, rowsQueue: [][][]any{{{int64(100), "b3BhcXVl", "signal_message", "d1"}}}}
	rr := httptest.NewRecorder()
	NewGetSenderKeyDistributionsHandler(GroupsDeps{PG: db})(rr, groupRequest(http.MethodGet, "/api/groups/"+behaviorGroupID+"/sender-key-distributions", "", 200))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"sender_uin":100`) {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if db.calls[0].args[1] != int64(200) {
		t.Fatalf("membership not bound to actor: %#v", db.calls[0].args)
	}
}
