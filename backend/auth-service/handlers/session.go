package handlers

import (
	"context"
	"time"

	"github.com/iceq/iceq/auth-service/models"
	"github.com/iceq/iceq/shared/jwt"
	"github.com/jackc/pgx/v5/pgxpool"
)

func issueSession(ctx context.Context, pool *pgxpool.Pool, manager *jwt.Manager, uin int64) (models.AuthTokens, error) {
	access, err := manager.Sign(uin, jwt.TokenTypeAccess)
	if err != nil {
		return models.AuthTokens{}, err
	}
	refresh, err := manager.Sign(uin, jwt.TokenTypeRefresh)
	if err != nil {
		return models.AuthTokens{}, err
	}

	hash := sha256Hex(refresh.Token)
	expiresAt := time.Now().UTC().Add(jwt.RefreshTokenTTL)
	if _, err := pool.Exec(ctx, qInsertRefreshToken, uin, hash, expiresAt); err != nil {
		return models.AuthTokens{}, err
	}

	return models.AuthTokens{
		AccessToken:  access.Token,
		RefreshToken: refresh.Token,
	}, nil
}
