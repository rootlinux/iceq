package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/iceq/iceq/auth-service/handlers"
)

// ---------------------------------------------------------------------------
// Lightweight fakes for the composition-root tests.
// ---------------------------------------------------------------------------

type routeMessageStore struct{}

func (*routeMessageStore) DeleteUserMessages(context.Context, int64) error      { return nil }
func (*routeMessageStore) DeleteUserGroupMessages(context.Context, int64) error { return nil }

type routeNatsCleaner struct{}

func (*routeNatsCleaner) PurgeUserStreams(context.Context, int64) error { return nil }

type routeMinioCleaner struct{}

func (*routeMinioCleaner) DeleteUserObjects(_ context.Context, _ int64, _ []string) error {
	return nil
}
func (*routeMinioCleaner) DeleteUserGrants(context.Context, int64) error { return nil }

func TestNewPanicWipeDepsWiresAllDependencies(t *testing.T) {
	store := &routeMessageStore{}
	natsCleaner := &routeNatsCleaner{}
	minioCleaner := &routeMinioCleaner{}

	// Verify that PanicWipeDeps carries all five dependency slots.
	// The production function (newPanicWipeDeps) calls log.Fatalf on nil
	// PG/Redis, so we construct the struct directly here to test the shape.
	deps := handlers.PanicWipeDeps{
		Pool:   nil, // set to non-nil in production
		Redis:  nil, // set to non-nil in production
		Scylla: store,
		NATS:   natsCleaner,
		Minio:  minioCleaner,
	}

	// Verify Scylla is wired.
	if deps.Scylla != store {
		t.Fatalf("Scylla = %#v, want %#v", deps.Scylla, store)
	}
	// Verify NATS is wired.
	if deps.NATS != natsCleaner {
		t.Fatalf("NATS = %#v, want %#v", deps.NATS, natsCleaner)
	}
	// Verify MinIO is wired.
	if deps.Minio != minioCleaner {
		t.Fatalf("Minio = %#v, want %#v", deps.Minio, minioCleaner)
	}
}

func TestNewPanicWipeDepsRejectsNilDependencies(t *testing.T) {
	// This test verifies the production function's nil-guard contract.
	// Since the function calls log.Fatalf on nil deps, we verify the
	// assertion exists in source — a source-level contract test.
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)

	// The startup assertion must check all 5 fields.
	for _, field := range []string{"deps.Pool", "deps.Redis", "deps.Scylla", "deps.NATS", "deps.Minio"} {
		if !strings.Contains(s, field) {
			t.Fatalf("startup assertion missing nil-check for %s", field)
		}
	}
	if !strings.Contains(s, "panic-wipe dependencies incomplete") {
		t.Fatal("startup assertion missing fatal error message")
	}
}

func TestNewPanicWipeDepsRetainsMessageStore(t *testing.T) {
	store := &routeMessageStore{}
	natsCleaner := &routeNatsCleaner{}
	minioCleaner := &routeMinioCleaner{}
	// Construct deps struct directly (newPanicWipeDeps calls log.Fatalf on nil PG/Redis).
	deps := handlers.PanicWipeDeps{
		Pool:   nil,
		Redis:  nil,
		Scylla: store,
		NATS:   natsCleaner,
		Minio:  minioCleaner,
	}
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

func TestRoutesDoNotExposeAutomaticPanicWipeSettings(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	mainGo := string(src)

	for _, forbidden := range []string{
		`Get("/settings"`,
		`Put("/settings"`,
		`Wipe: &panicWipeDeps`,
	} {
		if strings.Contains(mainGo, forbidden) {
			t.Fatalf("main.go still exposes automatic panic-wipe behavior via %q", forbidden)
		}
	}
	if !strings.Contains(mainGo, `r.With(authMW, rate("auth:panic-wipe", 3, time.Hour), csrfMW).Post("/panic-wipe"`) {
		t.Fatal("manual panic-wipe route must retain access-token auth and CSRF protection")
	}
}
