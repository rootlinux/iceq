package models

import "testing"

func TestIsReservedServerControlEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"account wiped", `{"type":"account_wiped","id":"1","ts":1,"payload":{}}`, true},
		{"mixed case duplicate cannot override exact type", `{"type":"account_wiped","TYPE":"message","id":"1","ts":1,"payload":{}}`, true},
		{"ordinary message", `{"type":"message","id":"1","ts":1,"payload":{}}`, false},
		{"malformed", `{"type":`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsReservedServerControlEnvelope([]byte(tc.raw)); got != tc.want {
				t.Fatalf("IsReservedServerControlEnvelope()=%v want %v", got, tc.want)
			}
		})
	}
}
