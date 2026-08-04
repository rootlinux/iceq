package main

import (
	"context"
	"errors"
	"testing"
)

type recordingWipedConnectionCloser struct {
	uins []int64
}

type fakeWipedAccountStateChecker struct {
	wiped bool
	err   error
}

func (r *recordingWipedConnectionCloser) CloseWiped(uin int64) {
	r.uins = append(r.uins, uin)
}

func (f fakeWipedAccountStateChecker) IsAccountWipedOrMissing(context.Context, int64) (bool, error) {
	return f.wiped, f.err
}

func TestHandleAccountWipedNotificationClosesOnlyTargetUIN(t *testing.T) {
	closer := &recordingWipedConnectionCloser{}
	checker := fakeWipedAccountStateChecker{wiped: true}
	handled, err := handleAccountWipedNotification(context.Background(), closer, checker, "account.wiped.10000001")
	if err != nil || !handled {
		t.Fatal("valid wipe notification was rejected")
	}
	if len(closer.uins) != 1 || closer.uins[0] != 10000001 {
		t.Fatalf("closed UINs = %v, want [10000001]", closer.uins)
	}

	for _, subject := range []string{
		"account.wiped.",
		"account.wiped.not-a-uin",
		"account.wiped.0",
		"account.wiped.-1",
		"notification.10000002",
		"account.wiped.10000002.extra",
	} {
		handled, err := handleAccountWipedNotification(context.Background(), closer, checker, subject)
		if err != nil {
			t.Fatalf("invalid subject %q returned error: %v", subject, err)
		}
		if handled {
			t.Fatalf("invalid subject %q was accepted", subject)
		}
	}
	if len(closer.uins) != 1 {
		t.Fatalf("invalid subjects closed connections: %v", closer.uins)
	}
}

func TestHandleAccountWipedNotificationRejectsUnverifiedLiveAccount(t *testing.T) {
	closer := &recordingWipedConnectionCloser{}
	handled, err := handleAccountWipedNotification(
		context.Background(), closer, fakeWipedAccountStateChecker{wiped: false}, "account.wiped.10000001",
	)
	if err != nil || handled {
		t.Fatalf("handled=%v err=%v, want false nil", handled, err)
	}
	if len(closer.uins) != 0 {
		t.Fatalf("unverified event closed connections: %v", closer.uins)
	}
}

func TestHandleAccountWipedNotificationFailsClosedOnLookupError(t *testing.T) {
	closer := &recordingWipedConnectionCloser{}
	wantErr := errors.New("postgres unavailable")
	handled, err := handleAccountWipedNotification(
		context.Background(), closer, fakeWipedAccountStateChecker{err: wantErr}, "account.wiped.10000001",
	)
	if handled || !errors.Is(err, wantErr) {
		t.Fatalf("handled=%v err=%v, want false %v", handled, err, wantErr)
	}
	if len(closer.uins) != 0 {
		t.Fatalf("lookup failure closed connections: %v", closer.uins)
	}
}
