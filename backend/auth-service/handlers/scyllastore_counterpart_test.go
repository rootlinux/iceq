package handlers

import "testing"

// TestDMCounterpartUINParsesOtherParticipant pins the parsing rules
// dmCounterpartUIN uses to find the surviving party of a DM conversation
// during panic-wipe cleanup. The rules mirror message-service/handlers'
// parseDMMembers exactly (canonical "dm:<min>:<max>", min < max) since both
// sides must agree on what counts as a valid conversation_id.
func TestDMCounterpartUINParsesOtherParticipant(t *testing.T) {
	tests := []struct {
		name           string
		conversationID string
		knownUIN       int64
		wantUIN        int64
		wantOK         bool
	}{
		{"known is min", "dm:100:200", 100, 200, true},
		{"known is max", "dm:100:200", 200, 100, true},
		{"unknown participant", "dm:100:200", 300, 0, false},
		{"wrong prefix", "group:100:200", 100, 0, false},
		{"self conversation rejected", "dm:100:100", 100, 0, false},
		{"reversed order rejected", "dm:200:100", 100, 0, false},
		{"non-numeric", "dm:abc:200", 100, 0, false},
		{"wrong segment count", "dm:100:200:300", 100, 0, false},
		{"empty string", "", 100, 0, false},
		{"zero participant rejected", "dm:0:200", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := dmCounterpartUIN(tt.conversationID, tt.knownUIN)
			if ok != tt.wantOK || (ok && got != tt.wantUIN) {
				t.Fatalf("dmCounterpartUIN(%q, %d) = (%d, %v), want (%d, %v)",
					tt.conversationID, tt.knownUIN, got, ok, tt.wantUIN, tt.wantOK)
			}
		})
	}
}
