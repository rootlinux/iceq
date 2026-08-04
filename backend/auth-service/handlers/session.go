package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/iceq/iceq/auth-service/models"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// execer abstracts the Exec method shared by *pgxpool.Pool and pgx.Tx.
// Defined here so issueSessionTx can accept either, keeping the non-
// transactional call-sites (register) unchanged while letting the login
// path issue the session inside its serialization transaction.
type execer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

func issueSession(ctx context.Context, pool *pgxpool.Pool, manager *jwt.Manager, uin int64) (models.AuthTokens, error) {
	return issueSessionTx(ctx, pool, manager, uin)
}

// issueSessionTx signs access+refresh tokens and persists the refresh-token
// hash using the provided executor (either a pool or a transaction). When
// called inside a transaction, the refresh-token row is committed or rolled
// back atomically with the caller's wiped-account check.
func issueSessionTx(ctx context.Context, ex execer, manager *jwt.Manager, uin int64) (models.AuthTokens, error) {
	access, err := manager.Sign(uin, jwt.TokenTypeAccess)
	if err != nil {
		return models.AuthTokens{}, fmt.Errorf("issue session: sign access token: %w", err)
	}
	refresh, err := manager.Sign(uin, jwt.TokenTypeRefresh)
	if err != nil {
		return models.AuthTokens{}, fmt.Errorf("issue session: sign refresh token: %w", err)
	}

	hash := sha256Hex(refresh.Token)
	expiresAt := time.Now().UTC().Add(jwt.RefreshTokenTTL)
	if _, err := ex.Exec(ctx, qInsertRefreshToken, uin, hash, expiresAt); err != nil {
		return models.AuthTokens{}, fmt.Errorf("issue session: insert refresh token: %w", err)
	}

	return models.AuthTokens{
		AccessToken:  access.Token,
		RefreshToken: refresh.Token,
	}, nil
}
