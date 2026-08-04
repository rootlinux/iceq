package client

import (
	"sync"
	"sync/atomic"
	"testing"

	"nhooyr.io/websocket"
)

func TestCloseSocketPreservesFirstProtocolClose(t *testing.T) {
	var mu sync.Mutex
	var closes []websocket.StatusCode
	c := &Client{
		closeSocketFn: func(code websocket.StatusCode, _ string) error {
			mu.Lock()
			closes = append(closes, code)
			mu.Unlock()
			return nil
		},
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.closeSocket(CloseCodeWiped, "account_wiped")
	}()
	go func() {
		defer wg.Done()
		c.closeSocket(websocket.StatusNormalClosure, "bye")
	}()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(closes) != 1 {
		t.Fatalf("socket close calls = %d, want exactly one", len(closes))
	}
}

func TestConcurrentCloseWipedEmitsOneTerminalSequence(t *testing.T) {
	var notifications atomic.Int32
	var closes atomic.Int32
	c := &Client{
		done: make(chan struct{}),
		writeWipeNotificationFn: func() error {
			notifications.Add(1)
			return nil
		},
		closeSocketFn: func(websocket.StatusCode, string) error {
			closes.Add(1)
			return nil
		},
	}

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.CloseWiped()
		}()
	}
	wg.Wait()

	if got := notifications.Load(); got != 1 {
		t.Fatalf("terminal notifications=%d want 1", got)
	}
	if got := closes.Load(); got != 1 {
		t.Fatalf("terminal closes=%d want 1", got)
	}
}

func TestTrySendRejectsReservedAccountWipedControl(t *testing.T) {
	c := &Client{send: make(chan []byte, 2)}
	reserved := []byte(`{"type":"account_wiped","id":"1","ts":1,"payload":{}}`)
	ordinary := []byte(`{"type":"message","id":"2","ts":1,"payload":{}}`)

	if c.TrySend(reserved) {
		t.Fatal("reserved terminal control entered generic client queue")
	}
	if !c.TrySend(ordinary) {
		t.Fatal("ordinary envelope was rejected")
	}
	if got := <-c.send; string(got) != string(ordinary) {
		t.Fatalf("queued envelope=%s", got)
	}
}

func TestCloseWipedCannotBeOverwrittenByNormalClose(t *testing.T) {
	var sequence []string
	var closes []websocket.StatusCode
	c := &Client{
		done: make(chan struct{}),
		writeWipeNotificationFn: func() error {
			sequence = append(sequence, "notify")
			return nil
		},
		closeSocketFn: func(code websocket.StatusCode, _ string) error {
			sequence = append(sequence, "close")
			closes = append(closes, code)
			return nil
		},
	}

	c.CloseWiped()
	c.closeSocket(websocket.StatusNormalClosure, "bye")

	if len(closes) != 1 || closes[0] != CloseCodeWiped {
		t.Fatalf("socket close calls = %v, want [%d]", closes, CloseCodeWiped)
	}
	if len(sequence) != 2 || sequence[0] != "notify" || sequence[1] != "close" {
		t.Fatalf("wipe shutdown sequence = %v, want [notify close]", sequence)
	}
}
