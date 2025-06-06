package usecase

import (
	"auth-service/internal/domain"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

// Про слой usecase.
// Здесь мы располагаем интерфейсами для работы со структурами domain,
// а также базы данных. Здесь определяется "Бизнес - логика", то какие
// мы используем методы и как обрабатываем структуры.
// Благодаря интерфейсам, можно просто работать с любой базой данных.

type userUseCase struct {
	repo        UserRepository
	sessionRepo SessionRepository
	pm          PasswordManager
	jwt         JWTService
}

var (
	passwordRe = regexp.MustCompile(`^[A-Za-z0-9]{6,32}$`)
	usernameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{4,11}$`)
	emailRe    = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
)

func NewUserUseCase(repo UserRepository, sessionRepo SessionRepository, pm PasswordManager, jwt JWTService) *userUseCase {
	return &userUseCase{
		repo:        repo,
		sessionRepo: sessionRepo,
		pm:          pm,
		jwt:         jwt,
	}
}

func newDomainUser(name, email, hashedPassword string) *domain.User {
	return &domain.User{
		Name:           name,
		Email:          email,
		HashedPassword: hashedPassword,
	}
}

func (uc *userUseCase) Register(ctx context.Context, name, email, password, ip, userAgent string) (*domain.User, string, string, error) {

	if err := uc.validateUsername(name); err != nil {
		return nil, "", "", fmt.Errorf("validation error: %w", err)
	}
	if err := uc.validateEmail(email); err != nil {
		return nil, "", "", fmt.Errorf("validation error: %w", err)
	}
	if err := uc.validatePassword(password); err != nil {
		return nil, "", "", fmt.Errorf("validation error: %w", err)
	}

	// unique email check
	_, err := uc.repo.FindByEmail(ctx, email)
	if err == nil {
		return nil, "", "", domain.ErrEmailTaken
	}
	if !errors.Is(err, domain.ErrUserNotFound) {
		return nil, "", "", fmt.Errorf("could not check email uniqueness: %w", err)
	}

	// uniqueness check for username
	_, err = uc.repo.FindByName(ctx, name)
	if err == nil {
		return nil, "", "", domain.ErrUsernameTaken
	}
	if !errors.Is(err, domain.ErrUserNotFound) {
		return nil, "", "", fmt.Errorf("could not check username uniqueness: %w", err)
	}

	// hash the password
	hashedPassword, err := uc.pm.Hash(password)
	if err != nil {
		return nil, "", "", fmt.Errorf("could not hash password: %w", err)
	}

	user := newDomainUser(name, email, hashedPassword)

	// Здесь в идеале должна начинаться транзакция
	id, err := uc.repo.Create(ctx, user)
	if err != nil {
		return nil, "", "", fmt.Errorf("could not create user: %w", err)
	}
	user.ID = id // <-- ВАЖНО: исправлен баг, ID теперь присваивается объекту

	accessToken, err := uc.jwt.GenerateAccessToken(name)
	if err != nil {
		return nil, "", "", fmt.Errorf("could not generate access token: %w", err)
	}

	refreshToken, expirationTime, err := uc.jwt.GenerateRefreshToken(name)
	if err != nil {
		return nil, "", "", fmt.Errorf("could not generate refresh token: %w", err)
	}

	session := &domain.UserSession{
		UserID:           user.ID,
		IP:               ip,
		UserAgent:        userAgent,
		RefreshTokenHash: uc.hashRefreshToken(refreshToken),
		ExpiresAt:        expirationTime,
	}

	if err := uc.sessionRepo.StoreRefreshToken(ctx, session); err != nil {
		// В случае ошибки здесь, созданный пользователь останется в БД.
		// Транзакция позволила бы откатить создание пользователя.
		return nil, "", "", fmt.Errorf("could not store refresh token: %w", err)
	}
	// Здесь транзакция должна быть закоммичена

	return user, accessToken, refreshToken, nil
}

func (uc *userUseCase) Login(ctx context.Context, email, password, ip, userAgent string) (*domain.User, string, string, error) {
	if err := uc.validateEmail(email); err != nil {
		return nil, "", "", fmt.Errorf("validation error: %w", err)
	}

	user, err := uc.repo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, "", "", domain.ErrInvalidCredentials
		}
		return nil, "", "", fmt.Errorf("could not find user: %w", err)
	}

	if !uc.pm.Verify(password, user.HashedPassword) {
		return nil, "", "", domain.ErrInvalidCredentials
	}

	accessToken, err := uc.jwt.GenerateAccessToken(user.Name)
	if err != nil {
		return nil, "", "", fmt.Errorf("could not generate access token: %w", err)
	}

	refreshToken, expirationTime, err := uc.jwt.GenerateRefreshToken(user.Name)
	if err != nil {
		return nil, "", "", fmt.Errorf("could not generate refresh token: %w", err)
	}

	session := &domain.UserSession{
		UserID:           user.ID,
		IP:               ip,
		UserAgent:        userAgent,
		RefreshTokenHash: uc.hashRefreshToken(refreshToken),
		ExpiresAt:        expirationTime,
	}

	if err := uc.sessionRepo.StoreRefreshToken(ctx, session); err != nil {
		return nil, "", "", fmt.Errorf("could not store refresh token: %w", err)
	}

	return user, accessToken, refreshToken, nil
}

func (uc *userUseCase) Update(ctx context.Context, userUpdate *domain.UserUpdate) error {
	if userUpdate.Name != nil {
		if err := uc.validateUsername(*userUpdate.Name); err != nil {
			return fmt.Errorf("validation error: %w", err)
		}
	}

	if userUpdate.Email != nil {
		if err := uc.validateEmail(*userUpdate.Email); err != nil {
			return fmt.Errorf("validation error: %w", err)
		}
	}

	if userUpdate.Password != nil {
		if err := uc.validatePassword(*userUpdate.Password); err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		hashedPassword, err := uc.pm.Hash(*userUpdate.Password)
		if err != nil {
			return fmt.Errorf("could not hash password: %w", err)
		}
		userUpdate.Password = &hashedPassword
	}

	return uc.repo.Update(ctx, userUpdate)
}

func (uc *userUseCase) Deactivate(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("%w: user ID cannot be zero", domain.ErrValidation)
	}
	return uc.repo.Deactivate(ctx, id)
}

func (uc *userUseCase) Activate(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("%w: user ID cannot be zero", domain.ErrValidation)
	}
	return uc.repo.Activate(ctx, id)
}

func (uc *userUseCase) validateUsername(name string) error {
	if len(name) < 5 || len(name) > 12 {
		return fmt.Errorf("%w: username length must be between 5 and 12 characters", domain.ErrValidation)
	}
	if !usernameRe.MatchString(name) {
		return fmt.Errorf("%w: username must start with a letter, be 5-12 characters long, and contain only letters and numbers", domain.ErrValidation)
	}
	return nil
}

// validateEmail проверяет корректность email.
func (uc *userUseCase) validateEmail(email string) error {
	if !emailRe.MatchString(email) {
		return fmt.Errorf("%w: invalid email format", domain.ErrValidation)
	}
	return nil
}

// validatePassword проверяет корректность пароля.
func (uc *userUseCase) validatePassword(password string) error {
	if !passwordRe.MatchString(password) {
		if len(password) < 6 || len(password) > 32 {
			return fmt.Errorf("%w: password length must be between 6 and 32 characters", domain.ErrValidation)
		}
		if !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(password) {
			return fmt.Errorf("%w: password can only contain letters (a-z, A-Z) and numbers (0-9)", domain.ErrValidation)
		}
		return fmt.Errorf("%w: password format is invalid (e.g. contains symbols)", domain.ErrValidation)
	}
	return nil
}

// hashRefreshToken хеширует токен для безопасного хранения в БД.
func (uc *userUseCase) hashRefreshToken(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	return hex.EncodeToString(hasher.Sum(nil))
}
