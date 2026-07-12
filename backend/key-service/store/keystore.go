// Package store is the key-service's persistence layer. It owns
// the SQL for prekey_bundles and one_time_prekeys and exposes a
// small, intention-revealing API to the handlers.
//
// The store is intentionally narrow: four methods, each
// corresponding to one user-facing endpoint. Splitting any
// further (e.g. a separate "GetSignedPrekey" and
// "GetOneTimePrekey") would force the handler to do two round
// trips and lose the atomicity of "the bundle I just saw is the
// bundle I'll act on".
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/iceq/iceq/key-service/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ----------------------------------------------------------------------------
// SQL. Every query is positional ($1, $2, ...) via pgx. We use
// $N rather than @name because pgx is the only driver; the
// numeric binding is faster to read and harder to typo
// (typo'd @name silently binds the wrong variable, typo'd $N is
// caught at the call site via the variadic args check).
// ----------------------------------------------------------------------------

const (
	// qSelectBundle fetches a user's prekey bundle. The
	// signed_prekey column is JSONB; we scan it into a
	// json.RawMessage and let the handler re-marshal it into
	// the response struct without re-parsing.
	qSelectBundle = `
		SELECT identity_key, signed_prekey, registration_id, spk_uploaded_at
		FROM prekey_bundles
		WHERE uin = $1
	`

	// qUpsertBundle creates or replaces a user's prekey
	// bundle. ON CONFLICT (uin) is the natural primary-key
	// collision; DO UPDATE rewrites identity_key,
	// signed_prekey, and bumps spk_uploaded_at to NOW().
	qUpsertBundle = `
		INSERT INTO prekey_bundles (uin, identity_key, signed_prekey, registration_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (uin) DO UPDATE
		SET identity_key    = EXCLUDED.identity_key,
		    signed_prekey   = EXCLUDED.signed_prekey,
		    registration_id = EXCLUDED.registration_id,
		    spk_uploaded_at = NOW()
	`

	// qConsumeOneTimePrekey atomically marks one unused
	// one-time prekey as used and returns it. The pattern is:
	//
	//   1. The CTE `picked` selects the lowest-numbered
	//      unused key for the user, taking a row lock with
	//      FOR UPDATE SKIP LOCKED so a concurrent consumer
	//      never sees the same row.
	//   2. The outer UPDATE marks the picked row as used.
	//   3. RETURNING hands the row back to the caller
	//      without a second round trip.
	//
	// SKIP LOCKED is the key: under load, two
	// /api/keys/bundle requests for the same user arrive
	// simultaneously. Without SKIP LOCKED, the second
	// request would block on the first's row lock; with it,
	// the second request immediately sees "that one's
	// taken, here's the next one". The end result: two
	// concurrent calls produce two different OPKs, never
	// the same one.
	//
	// Note: PostgreSQL does NOT allow `UPDATE ... ORDER BY
	// ... LIMIT ...` (no such syntax); the CTE pattern is
	// the correct shape.
	qConsumeOneTimePrekey = `
		WITH picked AS (
			SELECT id
			FROM one_time_prekeys
			WHERE uin = $1 AND used = false
			ORDER BY key_id ASC
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE one_time_prekeys
		SET used = true
		FROM picked
		WHERE one_time_prekeys.id = picked.id
		RETURNING one_time_prekeys.key_id, one_time_prekeys.public_key
	`

	// qInsertOneTimePrekeys adds a batch of new prekeys in
	// one round trip. UNNEST on parallel arrays is the
	// canonical Postgres batch-insert idiom: pgx encodes
	// []int and []string as int[] and text[], and Postgres
	// expands them row-wise.
	//
	// The ON CONFLICT clause swallows the
	// "this (uin, key_id) was already uploaded" case. We do
	// NOT want the whole batch to fail just because one key
	// is a duplicate — the client may have retried with a
	// partially-applied batch.
	qInsertOneTimePrekeys = `
		INSERT INTO one_time_prekeys (uin, key_id, public_key)
		SELECT $1, key_id, public_key
		FROM UNNEST($2::int[], $3::text[]) AS t(key_id, public_key)
		ON CONFLICT (uin, key_id) DO NOTHING
	`

	// qCountUnusedPrekeys counts how many one-time prekeys
	// the user still has available. The partial index
	// (uin, key_id) WHERE used = false makes this an
	// index-only count.
	qCountUnusedPrekeys = `
		SELECT count(*)::bigint
		FROM one_time_prekeys
		WHERE uin = $1 AND used = false
	`
)

// ----------------------------------------------------------------------------
// Sentinel errors. Handlers translate these to public error
// codes; the store never emits a public error code directly.
// ----------------------------------------------------------------------------

var (
	// ErrBundleNotFound means the user has never uploaded a
	// prekey bundle. Distinct from a DB error so the handler
	// can return 404 (not yet provisioned) rather than 500
	// (something is broken).
	ErrBundleNotFound = errors.New("store: prekey bundle not found")

	// ErrNoUnusedPrekey means the user has a bundle but no
	// unused one-time prekeys. Not an error condition — X3DH
	// can run with just the signed_prekey — but the handler
	// uses it to set the one_time_prekey field to null
	// instead of an empty object.
	ErrNoUnusedPrekey = errors.New("store: no unused prekey available")
)

// ----------------------------------------------------------------------------
// Keystore.
// ----------------------------------------------------------------------------

// Keystore wraps the pgx pool and exposes the four persistence
// operations the key-service needs. Constructed once in main.go
// and passed to the handlers.
type Keystore struct {
	Pool *pgxpool.Pool
}

// NewKeystore returns a Keystore backed by the given pool.
// The pool is owned by the caller; Keystore does not close it.
func NewKeystore(pool *pgxpool.Pool) *Keystore {
	return &Keystore{Pool: pool}
}

// ----------------------------------------------------------------------------
// GetBundle fetches the recipient's prekey bundle and atomically
// consumes one of their one-time prekeys. The returned
// OneTimePrekey may be nil (the user has no unused prekeys); the
// caller is expected to surface this as a null field in the
// response, not as an error.
//
// Errors:
//   - ErrBundleNotFound if the user has never uploaded a bundle
//   - any pgx error on a DB failure
// ----------------------------------------------------------------------------

func (k *Keystore) GetBundle(ctx context.Context, uin int64) (models.BundleResponse, error) {
	// 1. Fetch the bundle. signed_prekey is JSONB; we keep it
	// as RawMessage so we can re-emit it byte-for-byte in the
	// response without a re-marshal.
	var (
		identityKey    string
		signedJSON     json.RawMessage
		registrationID int
		uploadedAt     time.Time
	)
	err := k.Pool.QueryRow(ctx, qSelectBundle, uin).
		Scan(&identityKey, &signedJSON, &registrationID, &uploadedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.BundleResponse{}, ErrBundleNotFound
		}
		return models.BundleResponse{}, fmt.Errorf("store: select bundle: %w", err)
	}

	signedPrekey, err := models.DecodeSignedPrekeyJSON(signedJSON)
	if err != nil {
		// The DB row is malformed — our own INSERT wrote it,
		// so this would be a server-side bug, not a client
		// problem.
		return models.BundleResponse{}, fmt.Errorf("store: decode signed_prekey: %w", err)
	}

	resp := models.BundleResponse{
		UIN:            uin,
		IdentityKey:    identityKey,
		SignedPrekey:   signedPrekey,
		RegistrationID: registrationID,
	}

	// 2. Try to consume one OPK. The UPDATE is the atomic
	// step; a missing row (user has no OPKs) is not an error
	// — we just leave OneTimePrekey nil.
	var (
		consumedKeyID int
		consumedPub   string
	)
	err = k.Pool.QueryRow(ctx, qConsumeOneTimePrekey, uin).
		Scan(&consumedKeyID, &consumedPub)
	switch {
	case err == nil:
		// Got one. Attach it to the response.
		resp.OneTimePrekey = &models.OneTimePrekey{
			ID:        consumedKeyID,
			PublicKey: consumedPub,
		}
	case errors.Is(err, pgx.ErrNoRows):
		// No OPK available. Leave the field nil; the client
		// can still complete the X3DH handshake with the SPK
		// alone.
	default:
		return models.BundleResponse{}, fmt.Errorf("store: consume prekey: %w", err)
	}

	return resp, nil
}

// ----------------------------------------------------------------------------
// UpsertBundle stores (or replaces) a user's prekey bundle. The
// handler is responsible for authenticating the caller and
// confirming the bundle belongs to them; this method just
// persists what it's given.
//
// Errors:
//   - any pgx error on a DB failure (unique violation is
//     impossible here because the ON CONFLICT clause catches
//     it)
// ----------------------------------------------------------------------------

func (k *Keystore) UpsertBundle(ctx context.Context, uin int64, identityKey string, signedPrekey models.SignedPrekey, registrationID int) error {
	// The signed_prekey is a struct, but the column is JSONB.
	// We marshal it to bytes and pass it as $3; pgx encodes
	// []byte as a JSONB literal when the column type is JSONB
	// (it actually goes as a text parameter that Postgres
	// casts to JSONB on insert).
	signedBytes, err := json.Marshal(signedPrekey)
	if err != nil {
		// Marshalling a struct with only string and int
		// fields cannot fail in practice. Treat as a 500
		// bug if it ever does.
		return fmt.Errorf("store: marshal signed_prekey: %w", err)
	}

	if _, err := k.Pool.Exec(ctx, qUpsertBundle, uin, identityKey, signedBytes, registrationID); err != nil {
		return fmt.Errorf("store: upsert bundle: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// AddOneTimePrekeys appends a batch of prekeys to the user's
// pool. Duplicate (uin, key_id) pairs are silently dropped
// (ON CONFLICT DO NOTHING) so a partially-replayed batch
// doesn't fail the whole insert.
//
// Errors:
//   - any pgx error on a DB failure
// ----------------------------------------------------------------------------

func (k *Keystore) AddOneTimePrekeys(ctx context.Context, uin int64, prekeys []models.OneTimePrekey) error {
	if len(prekeys) == 0 {
		return nil
	}
	// Rename the loop variable to `p` to avoid shadowing
	// the receiver `k`. (Both names are valid; shadowing
	// compiles fine, but reading the loop body and not
	// knowing which `k` it refers to is a future bug
	// waiting to happen.)
	keyIDs := make([]int, len(prekeys))
	publicKeys := make([]string, len(prekeys))
	for i, p := range prekeys {
		keyIDs[i] = p.ID
		publicKeys[i] = p.PublicKey
	}
	if _, err := k.Pool.Exec(ctx, qInsertOneTimePrekeys, uin, keyIDs, publicKeys); err != nil {
		return fmt.Errorf("store: insert prekeys: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// CountUnusedPrekeys returns the number of one-time prekeys the
// user still has available. Used by the client to decide when
// to replenish.
// ----------------------------------------------------------------------------

func (k *Keystore) CountUnusedPrekeys(ctx context.Context, uin int64) (int, error) {
	var count int64
	if err := k.Pool.QueryRow(ctx, qCountUnusedPrekeys, uin).Scan(&count); err != nil {
		return 0, fmt.Errorf("store: count prekeys: %w", err)
	}
	// count is already int64 because of the ::bigint cast
	// in qCountUnusedPrekeys. int on every supported Go
	// platform is at least 32 bits; the count cannot
	// realistically exceed that.
	return int(count), nil
}
