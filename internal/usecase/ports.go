package usecase

import (
	"auth-service/internal/domain"
	"context"
	"time"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) (uint, error)
	Remove(ctx context.Context, id uint) error
	Deactivate(ctx context.Context, id uint) error
	Activate(ctx context.Context, id uint) error
	Update(ctx context.Context, userUpdate *domain.UserUpdate) error
	//UpdatePassword(ctx context.Context, password_hash string, id uint) error
	//UpdateName(ctx context.Context, name string, id uint) error
	//UpdateEmail(ctx context.Context, email string, id uint) error
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
	FindByID(ctx context.Context, id uint) (*domain.User, error)
	FindByName(ctx context.Context, name string) (*domain.User, error)
}

type SessionRepository interface {
	StoreRefreshToken(ctx context.Context, session *domain.UserSession) error
	DeactivateRefreshToken(ctx context.Context, session *domain.UserSession) error
	DeactivateAllRefreshTokens(ctx context.Context, userID uint) error
	ValidateAndUseRefreshToken(ctx context.Context, session *domain.UserSession) (bool, error)
}

type JWTService interface {
	GenerateAccessToken(username string) (string, error)
	GenerateRefreshToken(username string) (string, time.Time, error)
	ValidateToken(token string) (*domain.Claims, error)
}

type UserUseCase interface {
	Deactivate(ctx context.Context, id uint) error
	Activate(ctx context.Context, id uint) error
	Register(ctx context.Context, name, email, password, ip, userAgent string) (*domain.User, string, string, error)
	Login(ctx context.Context, email, password, ip, userAgent string) (*domain.User, string, string, error)
	Update(ctx context.Context, userUpdate *domain.UserUpdate) error
}

type PasswordManager interface {
	Hash(password string) (string, error)
	Verify(password, hashedPassword string) bool
}
