package main

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"testing"
)

type epochDB struct {
	row  pgx.Row
	args []any
}

func (d *epochDB) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	d.args = args
	return d.row
}

type epochRow struct{ err error }

func (r epochRow) Scan(...any) error { return r.err }
func TestMessageStoreIngestFailsClosedOnStaleEpoch(t *testing.T) {
	db := &epochDB{row: epochRow{err: errors.New("stale")}}
	if authorizeGroupMessageEpoch(context.Background(), db, "g", 7, 3) == nil {
		t.Fatal("stale epoch authorized")
	}
	if db.args[2] != int64(3) {
		t.Fatalf("epoch not bound: %#v", db.args)
	}
}
