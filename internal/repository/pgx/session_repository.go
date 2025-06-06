package repository

import (
	"auth-service/internal/domain"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type sessionRepository struct {
	db     *pgxpool.Pool
	logger *zap.Logger
}

func NewSessionRepository(db *pgxpool.Pool, logger *zap.Logger) *sessionRepository {
	return &sessionRepository{
		db:     db,
		logger: logger,
	}
}

func (r *sessionRepository) StoreRefreshToken(ctx context.Context, session *domain.UserSession) error {
	query := `INSERT INTO user_sessions (user_id, ip, user_agent, refresh_token, expires_at, created_at, is_active)
	 VALUES ($1, $2, $3, $4, $5, NOW(), true)`
	res, err := r.db.Exec(ctx, query, session.UserID, session.IP, session.UserAgent, session.RefreshTokenHash, session.ExpiresAt)
	if err != nil {
		r.logger.Error("Failed to store refresh token", zap.Error(err))
		return fmt.Errorf("repository: store refresh token: %w", err)
	}
	if res.RowsAffected() == 0 {
		r.logger.Warn("Store refresh token did not affect any rows", zap.Uint("userID", session.UserID))
		return domain.ErrNotFound
	}
	return nil
}

func (r *sessionRepository) DeactivateRefreshToken(ctx context.Context, session *domain.UserSession) error {
	query := `UPDATE user_sessions SET is_active = false WHERE user_id = $1 AND refresh_token = $2`
	res, err := r.db.Exec(ctx, query, session.UserID, session.RefreshTokenHash)
	if err != nil {
		r.logger.Error("Failed to deactivate refresh token", zap.Error(err))
		return fmt.Errorf("repository: deactivate refresh token: %w", err)
	}
	if res.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *sessionRepository) DeactivateAllRefreshTokens(ctx context.Context, userID uint) error {
	query := `UPDATE user_sessions SET is_active = false WHERE user_id = $1`
	res, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		r.logger.Error("Failed to deactivate all refresh tokens", zap.Error(err))
		return fmt.Errorf("repository: deactivate all refresh tokens: %w", err)
	}
	if res.RowsAffected() == 0 {
		r.logger.Warn("Deactivate all refresh tokens did not affect any rows", zap.Uint("userID", userID))
	}
	return nil
}

// Метод определяет возможность использования токена обновления.
// Но только в случае, если токен еще не истек, ip - адресс и user-agent совпадают.
func (r *sessionRepository) ValidateAndUseRefreshToken(ctx context.Context, session *domain.UserSession) (bool, error) {
	query := `SELECT id, ip, user_agent, refresh_token, expires_at FROM user_sessions WHERE user_id = $1 AND refresh_token = $2`
	row := r.db.QueryRow(ctx, query, session.UserID, session.RefreshTokenHash)
	s := &domain.UserSession{}
	if err := row.Scan(&s.ID, &s.IP, &s.UserAgent, &s.RefreshTokenHash, &s.ExpiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		r.logger.Error("Failed to validate and use refresh token", zap.Error(err))
		return false, fmt.Errorf("repository: validate and use refresh token: %w", err)
	}
	if s.ExpiresAt.Before(time.Now()) {
		return false, nil
	}
	if s.IP != session.IP || s.UserAgent != session.UserAgent {
		return false, nil
	}
	return true, nil
}
