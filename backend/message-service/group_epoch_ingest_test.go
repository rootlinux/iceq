package main

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"

	"github.com/gocql/gocql"
	"github.com/iceq/iceq/shared/models"
)

type epochDB struct {
	row  pgx.Row
	args []any
}

func TestGroupMessagePersistenceRequestCarriesAuthenticatedEpoch(t *testing.T) {
	groupID := gocql.TimeUUID()
	messageID := gocql.TimeUUID()
	createdAt := time.Now().UTC()
	payload := models.GroupMessagePayload{
		SenderUIN: 42, CryptoEpoch: 9, Ciphertext: []byte("opaque"), MsgType: "group_ciphertext",
	}
	req := newSaveGroupRequest(groupID, messageID, payload, createdAt)
	if req.CryptoEpoch != 9 || req.SenderUIN != 42 || string(req.Ciphertext) != "opaque" {
		t.Fatalf("persistence request lost authenticated payload fields: %#v", req)
	}
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
