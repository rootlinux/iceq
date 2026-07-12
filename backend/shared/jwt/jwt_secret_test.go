package jwt

// Verifies the F-2 fix: NewManager must reject weak signing
// secrets at process start, not silently boot with them.
//
// The test is a quick proof-of-correctness, not a comprehensive
// unit test. We use lazy-construct (no actual network I/O)
// non-nil rdb and pg sentinels: redis.NewClient returns a
// non-nil client without connecting, and pgxpool.New returns
// a non-nil pool without connecting (it dials on first use).
// This way the nil-pool checks AFTER the secret checks don't
// fire, and we can exercise the secret-policy code path in
// isolation.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func TestNewManager_SecretPolicy(t *testing.T) {
	// Non-nil sentinels. Construction is lazy — no network
	// I/O happens. If a future code path tries to USE these
	// (e.g. a "round-trip the token" test), the test will
	// fail with a connection error, which is the right
	// outcome (we only want to test the constructor here).
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0"})
	pg, err := pgxpool.New(context.Background(),
		"postgres://x:y@127.0.0.1:1/z?sslmode=disable")
	if err != nil {
		t.Fatalf("sentinel pgxpool.New: %v", err)
	}

	cases := []struct {
		name      string
		secret    string
		wantErr   error
		wantSubst string
	}{
		{
			name:    "empty secret returns ErrMissingSecret",
			secret:  "",
			wantErr: ErrMissingSecret,
		},
		{
			name:      "literal 'changeme' (8 bytes) is rejected by length check",
			secret:    "changeme",
			wantSubst: "too weak",
		},
		{
			name:      "'CHANGEME' upper-case is also rejected by length check",
			secret:    "CHANGEME",
			wantSubst: "too weak",
		},
		{
			name:      "31-byte secret is rejected by length check",
			secret:    strings.Repeat("a", minSecretBytes-1),
			wantSubst: "too weak",
		},
		{
			name:      "exact 32-byte secret is accepted (control)",
			secret:    strings.Repeat("a", minSecretBytes),
			wantSubst: "", // nil error
		},
		{
			name:      "32-byte secret with 'dev' as a substring is accepted (deny-list is exact-match, not substring)",
			secret:    "dev-environment-secret-padded-to-32-bytes",
			wantSubst: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewManager(tc.secret, rdb, pg)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("want errors.Is(%v), got %v", tc.wantErr, err)
				}
			case tc.wantSubst != "":
				if err == nil {
					t.Fatalf("want error containing %q, got nil", tc.wantSubst)
				}
				if !strings.Contains(strings.ToLower(err.Error()), tc.wantSubst) {
					t.Fatalf("want error containing %q, got %q", tc.wantSubst, err.Error())
				}
			default:
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
			}
		})
	}
}
