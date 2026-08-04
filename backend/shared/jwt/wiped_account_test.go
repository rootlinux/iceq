package jwt

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
)

type wipeRow struct{ wiped bool }

func (r wipeRow) Scan(dest ...any) error { *(dest[0].(*bool)) = r.wiped; return nil }

type wipePG struct{ wiped bool }

func (p wipePG) QueryRow(context.Context, string, ...any) pgx.Row { return wipeRow{wiped: p.wiped} }
func (p wipePG) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func TestVerifyRejectsDurablyWipedAccountBeforeUnavailableRedis(t *testing.T) {
	m := &Manager{
		secret: []byte("0123456789abcdef0123456789abcdef"),
		rdb:    redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}),
		pg:     wipePG{wiped: true},
	}
	signed, err := m.Sign(10000001, TokenTypeAccess)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Verify(context.Background(), signed.Token, TokenTypeAccess)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("Verify error = %v, want ErrTokenRevoked", err)
	}
}

func TestIsAccountWipedReturnsDurableMarker(t *testing.T) {
	m := &Manager{pg: wipePG{wiped: true}}
	wiped, err := m.IsAccountWiped(context.Background(), 10000001)
	if err != nil || !wiped {
		t.Fatalf("wiped=%v err=%v, want true nil", wiped, err)
	}
}

func TestIsAccountWipedOrMissingReturnsDurableDeletionState(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  bool
	}{
		{name: "live account", got: false},
		{name: "wiped or missing account", got: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &Manager{pg: wipePG{wiped: tc.got}}
			wiped, err := m.IsAccountWipedOrMissing(context.Background(), 10000001)
			if err != nil || wiped != tc.got {
				t.Fatalf("wiped=%v err=%v, want %v nil", wiped, err, tc.got)
			}
		})
	}
}
