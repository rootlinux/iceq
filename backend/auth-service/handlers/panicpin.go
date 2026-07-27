// Package handlers — panicpin.go
//
// The panic-wipe PIN is a second, independent factor gating the
// irreversible panic-wipe action (see panicwipe.go). It exists for a
// narrower threat than the login password: a session that is already
// authenticated (an unlocked laptop, a shared/borrowed device, a stolen
// session cookie) can otherwise trigger the wipe with a single click. The
// PIN is deliberately NOT the login password -- reusing it would add no
// protection against exactly the threat this feature targets, since an
// attacker with an open session frequently also has the saved password.
//
// The PIN is optional (NULL by default): panic-wipe behaves exactly as
// before unless the user opts in from Settings. Setting, changing, or
// clearing the PIN itself requires re-entering the login password, the
// same re-authentication bar any other security-relevant change should
// clear.
package handlers

import (
	"context"
	"net/http"
	"regexp"

	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

var panicPinPattern = regexp.MustCompile(`^[0-9]{4}$`)

const (
	// qSetPanicPin upserts the hash. ON CONFLICT covers both the
	// first-ever PIN (INSERT) and a later change (UPDATE) in one
	// statement; user_security_settings has no writer that would race
	// this beyond the panic-wipe DELETE, which only ever removes rows.
	qSetPanicPin = `
		INSERT INTO user_security_settings (uin, panic_pin_hash)
		VALUES ($1, $2)
		ON CONFLICT (uin) DO UPDATE SET panic_pin_hash = EXCLUDED.panic_pin_hash
	`
	qClearPanicPin = `
		UPDATE user_security_settings SET panic_pin_hash = NULL WHERE uin = $1
	`
	// qSelectPanicPinHash may return zero rows (no user_security_settings
	// row yet) or a row with a NULL hash (row exists, PIN never set) --
	// both mean "no PIN configured" to the caller.
	qSelectPanicPinHash = `SELECT panic_pin_hash FROM user_security_settings WHERE uin = $1`

	qSelectPasswordHashByUIN = `SELECT password_hash FROM users WHERE uin = $1`
)

// SetPanicPinDeps wires the panic-PIN endpoint. LookupPasswordHash and
// SetPin default to Postgres-backed implementations via Pool; tests
// inject stubs so the handler contract stays unit-testable without a
// live database, matching the Wipe-injection pattern in panicwipe.go.
type SetPanicPinDeps struct {
	Pool               *pgxpool.Pool
	LookupPasswordHash func(ctx context.Context, uin int64) (string, error)
	// SetPin persists the new hash, or clears the PIN when hash == "".
	SetPin func(ctx context.Context, uin int64, hash string) error
}

type setPanicPinRequest struct {
	CurrentPassword string `json:"current_password"`
	// Pin is exactly 4 digits to set/replace the PIN, or "" to remove it.
	Pin string `json:"pin"`
}

// NewSetPanicPinHandler mounts PUT /api/auth/panic-pin.
func NewSetPanicPinHandler(deps SetPanicPinDeps) http.HandlerFunc {
	if deps.LookupPasswordHash == nil {
		pool := deps.Pool
		deps.LookupPasswordHash = func(ctx context.Context, uin int64) (string, error) {
			var hash string
			err := pool.QueryRow(ctx, qSelectPasswordHashByUIN, uin).Scan(&hash)
			return hash, err
		}
	}
	if deps.SetPin == nil {
		pool := deps.Pool
		deps.SetPin = func(ctx context.Context, uin int64, hash string) error {
			if hash == "" {
				_, err := pool.Exec(ctx, qClearPanicPin, uin)
				return err
			}
			_, err := pool.Exec(ctx, qSetPanicPin, uin, hash)
			return err
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}
		var req setPanicPinRequest
		if !decodeJSON(w, r, &req, 1024) {
			return
		}
		if req.Pin != "" && !panicPinPattern.MatchString(req.Pin) {
			writeError(w, http.StatusBadRequest, "INVALID_PIN", "pin must be exactly 4 digits")
			return
		}

		ctx := r.Context()
		storedPasswordHash, err := deps.LookupPasswordHash(ctx, uin)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "PANIC_PIN_UNAVAILABLE", "could not verify account")
			return
		}
		if !verifyPassword(storedPasswordHash, req.CurrentPassword).OK {
			writeError(w, http.StatusUnauthorized, "INVALID_PASSWORD", "current password is incorrect")
			return
		}

		if req.Pin == "" {
			if err := deps.SetPin(ctx, uin, ""); err != nil {
				writeError(w, http.StatusServiceUnavailable, "PANIC_PIN_UNAVAILABLE", "could not update pin")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		hash, err := hashPassword(req.Pin)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "PANIC_PIN_UNAVAILABLE", "could not update pin")
			return
		}
		if err := deps.SetPin(ctx, uin, hash); err != nil {
			writeError(w, http.StatusServiceUnavailable, "PANIC_PIN_UNAVAILABLE", "could not update pin")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
