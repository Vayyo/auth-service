package repository

import (
	"auth-service/internal/domain"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type userRepository struct {
	db     *pgxpool.Pool
	logger *zap.Logger
}

func NewUserRepository(db *pgxpool.Pool, logger *zap.Logger) *userRepository {
	return &userRepository{
		db:     db,
		logger: logger,
	}
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) (uint, error) {
	query := `INSERT INTO users (name, email, password_hash, created_at, updated_at, is_active)
	 VALUES ($1, $2, $3, NOW(), NOW(), true) RETURNING id`
	var id uint
	err := r.db.QueryRow(ctx, query, user.Name, user.Email, user.HashedPassword).Scan(&id)
	if err != nil {
		r.logger.Error("Failed to create user", zap.Error(err))
		return 0, fmt.Errorf("repository: create user: %w", err)
	}
	return id, nil
}

func (r *userRepository) Remove(ctx context.Context, id uint) error {
	query := `DELETE FROM users WHERE id = $1`
	res, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("Failed to remove user", zap.Error(err))
		return fmt.Errorf("repository: remove user: %w", err)
	}
	if res.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *userRepository) Deactivate(ctx context.Context, id uint) error {
	query := `UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1`
	res, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("Failed to deactivate user", zap.Error(err))
		return fmt.Errorf("repository: deactivate user: %w", err)
	}
	if res.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *userRepository) Activate(ctx context.Context, id uint) error {
	query := `UPDATE users SET is_active = true, updated_at = NOW() WHERE id = $1`
	res, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("Failed to activate user", zap.Error(err))
		return fmt.Errorf("repository: activate user: %w", err)
	}
	if res.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *userRepository) UpdatePassword(ctx context.Context, password_hash string, id uint) error {
	query := `UPDATE users set password_hash = $1, updated_at = NOW() where id = $2`
	res, err := r.db.Exec(ctx, query, password_hash, id)
	if err != nil {
		r.logger.Error("Failed to update user password", zap.Error(err))
		return fmt.Errorf("repository: update user password: %w", err)
	}
	if res.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *userRepository) UpdateName(ctx context.Context, name string, id uint) error {
	query := `UPDATE users set name = $1, updated_at = NOW() where id = $2`
	res, err := r.db.Exec(ctx, query, name, id)
	if err != nil {
		r.logger.Error("Failed to update user name", zap.Error(err))
		return fmt.Errorf("repository: update user name: %w", err)
	}
	if res.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *userRepository) UpdateEmail(ctx context.Context, email string, id uint) error {
	query := `UPDATE users set email = $1, updated_at = NOW() where id = $2`
	res, err := r.db.Exec(ctx, query, email, id)
	if err != nil {
		r.logger.Error("Failed to update user email", zap.Error(err))
		return fmt.Errorf("repository: update user email: %w", err)
	}
	if res.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *userRepository) Update(ctx context.Context, userUpdate *domain.UserUpdate) error {
	var err error
	if userUpdate.Name != nil {
		if e := r.UpdateName(ctx, *userUpdate.Name, userUpdate.ID); e != nil {
			err = errors.Join(err, e)
		}
	}
	if userUpdate.Email != nil {
		if e := r.UpdateEmail(ctx, *userUpdate.Email, userUpdate.ID); e != nil {
			err = errors.Join(err, e)
		}
	}
	if userUpdate.Password != nil {
		if e := r.UpdatePassword(ctx, *userUpdate.Password, userUpdate.ID); e != nil {
			err = errors.Join(err, e)
		}
	}
	return err
}

func (r *userRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `SELECT id, name, email, password_hash, created_at, updated_at, is_active FROM users WHERE email = $1`
	row := r.db.QueryRow(ctx, query, email)
	user := &domain.User{}
	if err := row.Scan(&user.ID, &user.Name, &user.Email, &user.HashedPassword, &user.CreatedAt, &user.UpdatedAt, &user.IsActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		r.logger.Error("Failed to find user by email", zap.Error(err))
		return nil, fmt.Errorf("repository: find user by email: %w", err)
	}
	return user, nil
}

func (r *userRepository) FindByID(ctx context.Context, id uint) (*domain.User, error) {
	query := `SELECT id, name, email, password_hash, created_at, updated_at, is_active from users where id = $1`
	row := r.db.QueryRow(ctx, query, id)
	user := &domain.User{}
	if err := row.Scan(&user.ID, &user.Name, &user.Email, &user.HashedPassword, &user.CreatedAt, &user.UpdatedAt, &user.IsActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		r.logger.Error("Failed to find user by ID", zap.Error(err))
		return nil, fmt.Errorf("repository: find user by ID: %w", err)
	}
	return user, nil
}

func (r *userRepository) FindByName(ctx context.Context, name string) (*domain.User, error) {
	query := `SELECT id, name, email, password_hash, created_at, updated_at, is_active FROM users WHERE name = $1`
	row := r.db.QueryRow(ctx, query, name)
	user := &domain.User{}
	if err := row.Scan(&user.ID, &user.Name, &user.Email, &user.HashedPassword, &user.CreatedAt, &user.UpdatedAt, &user.IsActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		r.logger.Error("Failed to find user by name", zap.Error(err))
		return nil, fmt.Errorf("repository: find user by name: %w", err)
	}
	return user, nil
}
