package main

import (
	"testing"

	"github.com/nats-io/nats.go"
)

func TestNATSTokenOption(t *testing.T) {
	t.Run("adds configured token", func(t *testing.T) {
		t.Setenv("ICEQ_NATS_TOKEN", "test-only-token")

		opts := nats.GetDefaultOptions()
		for _, apply := range natsTokenOption() {
			if err := apply(&opts); err != nil {
				t.Fatalf("apply option: %v", err)
			}
		}

		if opts.Token != "test-only-token" {
			t.Fatalf("token = %q, want configured token", opts.Token)
		}
	})

	t.Run("keeps anonymous local smoke compatibility when unset", func(t *testing.T) {
		t.Setenv("ICEQ_NATS_TOKEN", "")

		if got := len(natsTokenOption()); got != 0 {
			t.Fatalf("option count = %d, want 0", got)
		}
	})
}
