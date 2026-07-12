package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/iceq/iceq/auth-service/models"
	"github.com/iceq/iceq/shared/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type MeDeps struct {
	Pool *pgxpool.Pool
}

// NewMeHandler serves GET /api/auth/me behind BearerAuth.
func NewMeHandler(deps MeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin, ok := middleware.GetUIN(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "AUTH_MISSING_BEARER", "Authorization header is required")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		var (
			resp      models.AuthUser
			createdAt time.Time
		)
		err := deps.Pool.QueryRow(ctx, qSelectUserPublicByUIN, uin).
			Scan(&resp.UIN, &resp.Username, &resp.Email, &createdAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "USER_NOT_FOUND", "authenticated user does not exist")
				return
			}
			writeDBError(w, err, "me: select user")
			return
		}

		resp.CreatedAt = &createdAt
		writeJSON(w, http.StatusOK, resp)
	}
}
