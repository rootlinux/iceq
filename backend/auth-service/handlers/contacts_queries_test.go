package handlers

import (
	"strings"
	"testing"
)

func TestContactQueriesPreserveRequesterDirection(t *testing.T) {
	if !strings.Contains(qUpsertContact, "requested_by_uin") {
		t.Fatal("qUpsertContact must persist requested_by_uin")
	}
	if !strings.Contains(qListContactsForOwner, "incoming") || !strings.Contains(qListContactsForOwner, "outgoing") {
		t.Fatal("qListContactsForOwner must expose pending request direction")
	}
}

func TestAcceptContactRequiresIncomingRequester(t *testing.T) {
	if !strings.Contains(qAcceptContact, "requested_by_uin = $2") {
		t.Fatal("qAcceptContact must only accept requests initiated by the path UIN")
	}
	if !strings.Contains(qAcceptContactReverse, "requested_by_uin = $2") {
		t.Fatal("qAcceptContactReverse must only mirror the same incoming request")
	}
}
