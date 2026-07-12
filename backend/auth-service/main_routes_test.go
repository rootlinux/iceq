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
		`}), csrfMW).Post("/logout"`,
		`}), csrfMW).Put("/settings"`,
		`}), csrfMW).Post("/panic-wipe"`,
		`r.With(authMW, middleware.RequireCSRF).Post("/"`,
		`r.With(authMW, middleware.RequireCSRF).Put("/{target_uin}/accept"`,
		`r.With(authMW, middleware.RequireCSRF).Put("/{target_uin}/block"`,
		`r.With(authMW, middleware.RequireCSRF).Delete("/{target_uin}"`,
	} {
		if !strings.Contains(mainGo, want) {
			t.Fatalf("main.go does not contain CSRF route wiring %q", want)
		}
	}
}
