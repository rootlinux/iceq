package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

type routeMessageStore struct{}

func (*routeMessageStore) DeleteUserMessages(context.Context, int64) error      { return nil }
func (*routeMessageStore) DeleteUserGroupMessages(context.Context, int64) error { return nil }

func TestNewPanicWipeDepsRetainsMessageStore(t *testing.T) {
	store := &routeMessageStore{}
	deps := newPanicWipeDeps(nil, nil, store)
	if deps.Scylla != store {
		t.Fatalf("Scylla = %#v, want %#v", deps.Scylla, store)
	}
}

func TestStateChangingCookieRoutesRequireCSRF(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	mainGo := string(src)

	for _, want := range []string{
		`AllowedHeaders:   []string{"Authorization", "Content-Type", middleware.CSRFHeaderName}`,
		`r.With(csrfMW).Post("/refresh"`,
		`rate("auth:logout", 10, time.Minute), csrfMW).Post("/logout"`,
		`rate("auth:settings:write", 10, time.Minute), csrfMW).Put("/settings"`,
		`rate("auth:panic-wipe", 3, time.Hour), csrfMW).Post("/panic-wipe"`,
		`contactRate("contacts:add", 30), middleware.RequireCSRF).Post("/"`,
		`contactRate("contacts:accept", 30), middleware.RequireCSRF).Put("/{target_uin}/accept"`,
		`contactRate("contacts:block", 30), middleware.RequireCSRF).Put("/{target_uin}/block"`,
		`contactRate("contacts:remove", 30), middleware.RequireCSRF).Delete("/{target_uin}"`,
	} {
		if !strings.Contains(mainGo, want) {
			t.Fatalf("main.go does not contain CSRF route wiring %q", want)
		}
	}
}
