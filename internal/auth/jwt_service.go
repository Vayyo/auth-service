package auth

import (
	"fmt"
	"time"

	"auth-service/internal/domain"

	"github.com/golang-jwt/jwt/v5"
)

// JWTService представляет собой сервис для генерации и проверки JWT-токенов.
// Хранит секретный ключ и сроки действия токенов.
type JWTService struct {
	secretKey       string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

// NewJWTService создает новый экземпляр JWTService с заданными параметрами.
// secretKey - секретный ключ для подписи JWT-токенов.
// accessTokenTTL - время жизни JWT-токена доступа.
// refreshTokenTTL - время жизни JWT-токена обновления.
func NewJWTService(secretKey string, accessTokenTTL, refreshTokenTTL time.Duration) *JWTService {
	return &JWTService{
		secretKey:       secretKey,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
}

// GenerateAccessToken генерирует новый JWT-токен доступа для указанного имени пользователя.
// username - имя пользователя для которого генерируется токен.
// Возвращает строку с JWT-токеном и ошибку, если она возникла.
func (s *JWTService) GenerateAccessToken(username string) (string, error) {
	expirationTime := time.Now().Add(s.accessTokenTTL)
	claims := &domain.Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "auth-service",
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.secretKey))
	if err != nil {
		return "", fmt.Errorf("error while generation access token: %w", err)
	}

	return tokenString, nil
}

// GenerateRefreshToken генерирует новый JWT-токен обновления для указанного имени пользователя.
// username - имя пользователя для которого генерируется токен.
// Возвращает строку с JWT-токеном и ошибку, если она возникла.
func (s *JWTService) GenerateRefreshToken(username string) (string, time.Time, error) {
	expirationTime := time.Now().Add(s.refreshTokenTTL)
	claims := &domain.Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "auth-service",
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.secretKey))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("error while generation refresh token: %w", err)
	}

	return tokenString, expirationTime, nil
}

// ValidateToken проверяет и парсит JWT-токен.
// tokenString - строка с JWT-токеном.
// Возвращает структуру Claims и ошибку, если она возникла.
func (s *JWTService) ValidateToken(tokenString string) (*domain.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected sign method: %v", token.Header["alg"])
		}
		return []byte(s.secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("error while validation token: %w", err)
	}

	claims, ok := token.Claims.(*domain.Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
