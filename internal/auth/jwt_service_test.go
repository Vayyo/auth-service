package auth

import (
	"strings"
	"testing"
	"time"
)

const (
	testSecretKey          = "test-secret-key"
	testUsername           = "testuser"
	shortAccessTokenTTL    = 50 * time.Millisecond // Короткое время для теста истечения срока
	defaultAccessTokenTTL  = 15 * time.Minute
	defaultRefreshTokenTTL = 7 * 24 * time.Hour
)

func TestNewJWTService(t *testing.T) {
	service := NewJWTService(testSecretKey, defaultAccessTokenTTL, defaultRefreshTokenTTL)

	if service.secretKey != testSecretKey {
		t.Errorf("Expected secret key %s, got %s", testSecretKey, service.secretKey)
	}
	if service.accessTokenTTL != defaultAccessTokenTTL {
		t.Errorf("Expected access token TTL %v, got %v", defaultAccessTokenTTL, service.accessTokenTTL)
	}
	if service.refreshTokenTTL != defaultRefreshTokenTTL {
		t.Errorf("Expected refresh token TTL %v, got %v", defaultRefreshTokenTTL, service.refreshTokenTTL)
	}
}

func TestJWTService_GenerateAccessToken(t *testing.T) {
	service := NewJWTService(testSecretKey, defaultAccessTokenTTL, defaultRefreshTokenTTL)

	tokenString, err := service.GenerateAccessToken(testUsername)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	if tokenString == "" {
		t.Fatal("Generated access token is empty")
	}

	// Проверим базовую структуру JWT (3 части, разделенные точками)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}

	claims, err := service.ValidateToken(tokenString) // Используем ValidateToken для проверки
	if err != nil {
		t.Fatalf("Failed to validate generated access token: %v", err)
	}

	if claims.Username != testUsername {
		t.Errorf("Expected username %s, got %s", testUsername, claims.Username)
	}
	if claims.Subject != testUsername {
		t.Errorf("Expected subject %s, got %s", testUsername, claims.Subject)
	}
	if claims.Issuer != "auth-service" {
		t.Errorf("Expected issuer 'auth-service', got %s", claims.Issuer)
	}

	expectedExpiresAt := time.Now().Add(defaultAccessTokenTTL)
	// Допускаем небольшую дельту из-за времени выполнения
	if claims.ExpiresAt.Time.Unix() < time.Now().Unix() || claims.ExpiresAt.Time.Unix() > expectedExpiresAt.Add(5*time.Second).Unix() {
		t.Errorf("Token expiration time is not within the expected range. Expected around %v, got %v", expectedExpiresAt, claims.ExpiresAt.Time)
	}
}

func TestJWTService_GenerateRefreshToken(t *testing.T) {
	service := NewJWTService(testSecretKey, defaultAccessTokenTTL, defaultRefreshTokenTTL)

	tokenString, expirationTime, err := service.GenerateRefreshToken(testUsername)
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	if tokenString == "" {
		t.Fatal("Generated refresh token is empty")
	}
	if expirationTime.IsZero() {
		t.Fatal("Generated refresh token expiration time is zero")
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}

	claims, err := service.ValidateToken(tokenString)
	if err != nil {
		t.Fatalf("Failed to validate generated refresh token: %v", err)
	}

	if claims.Username != testUsername {
		t.Errorf("Expected username %s, got %s", testUsername, claims.Username)
	}
	if claims.Subject != testUsername {
		t.Errorf("Expected subject %s, got %s", testUsername, claims.Subject)
	}
	if claims.Issuer != "auth-service" {
		t.Errorf("Expected issuer 'auth-service', got %s", claims.Issuer)
	}

	expectedExpiresAt := time.Now().Add(defaultRefreshTokenTTL)
	if claims.ExpiresAt.Time.Unix() < time.Now().Unix() || claims.ExpiresAt.Time.Unix() > expectedExpiresAt.Add(5*time.Second).Unix() {
		t.Errorf("Token expiration time is not within the expected range. Expected around %v, got %v", expectedExpiresAt, claims.ExpiresAt.Time)
	}
}

func TestJWTService_ValidateToken(t *testing.T) {
	service := NewJWTService(testSecretKey, defaultAccessTokenTTL, defaultRefreshTokenTTL)
	serviceShortTTL := NewJWTService(testSecretKey, shortAccessTokenTTL, defaultRefreshTokenTTL)
	serviceWrongKey := NewJWTService("another-secret-key", defaultAccessTokenTTL, defaultRefreshTokenTTL)

	// 1. Успешная валидация
	t.Run("ValidToken", func(t *testing.T) {
		tokenString, _ := service.GenerateAccessToken(testUsername)
		claims, err := service.ValidateToken(tokenString)
		if err != nil {
			t.Fatalf("Expected valid token, but got error: %v", err)
		}
		if claims.Username != testUsername {
			t.Errorf("Expected username %s, got %s", testUsername, claims.Username)
		}
	})

	// 2. Ошибка валидации просроченного токена
	t.Run("ExpiredToken", func(t *testing.T) {
		tokenString, _ := serviceShortTTL.GenerateAccessToken(testUsername)
		time.Sleep(shortAccessTokenTTL + 10*time.Millisecond) // Ждем истечения срока
		_, err := serviceShortTTL.ValidateToken(tokenString)
		if err == nil {
			t.Fatal("Expected error for expired token, but got nil")
		}
		// Ошибка должна быть типа jwt.ErrTokenExpired или содержать "token is expired"
		// jwt.ErrTokenExpired не экспортируется напрямую из-за обертывания в fmt.Errorf
		if !strings.Contains(err.Error(), "token is expired") && !strings.Contains(err.Error(), "token has invalid claims: token is expired") {
			t.Errorf("Expected token expired error, got: %v", err)
		}
	})

	// 3. Ошибка валидации токена с неверной подписью
	t.Run("InvalidSignature", func(t *testing.T) {
		tokenString, _ := service.GenerateAccessToken(testUsername)
		_, err := serviceWrongKey.ValidateToken(tokenString)
		if err == nil {
			t.Fatal("Expected error for token with invalid signature, but got nil")
		}
		if !strings.Contains(err.Error(), "signature is invalid") {
			t.Errorf("Expected invalid signature error, got: %v", err)
		}
	})

	// 4. Ошибка валидации токена с неожиданным методом подписи
	t.Run("UnexpectedSigningMethod", func(t *testing.T) {
		// Фейковый токен с "неправильным" алгоритмом в заголовке
		// Header: { "alg": "ES256", "typ": "JWT" }
		// Payload: { "username": "testuser", "exp": <далекое будущее>, "iss": "auth-service" }
		// Подпись: простая валидная base64url строка, например, от "sig"
		fakeTokenWrongAlg := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3R1c2VyIiwiZXhwIjoyMTQ3NDgzNjQ3LCJpc3MiOiJhdXRoLXNlcnZpY2UifQ.c2ln"

		// Наш ValidateToken внутри вызывает jwt.ParseWithClaims с функцией проверки ключа,
		// которая специфично проверяет token.Method.(*jwt.SigningMethodHMAC).
		// Таким образом, передача токена с alg: ES256 должна вызвать ошибку "unexpected signing method".
		_, err := service.ValidateToken(fakeTokenWrongAlg)

		if err == nil {
			t.Fatal("Expected error for token with unexpected signing method, but got nil")
		}
		if !strings.Contains(err.Error(), "unexpected signing method: ES256") && !strings.Contains(err.Error(), "unexpected sign method: ES256") { // Добавлена проверка на вариант без g
			t.Errorf("Expected 'unexpected signing method: ES256' error, got: %v", err)
		}
	})

	// 5. Ошибка валидации некорректного (malformed) токена
	t.Run("MalformedToken", func(t *testing.T) {
		malformedToken := "not.a.jwt.token"
		_, err := service.ValidateToken(malformedToken)
		if err == nil {
			t.Fatal("Expected error for malformed token, but got nil")
		}
		// Ошибка может быть разной в зависимости от того, какая часть токена некорректна
		// jwt-go возвращает "token contains an invalid number of segments" или "token is malformed"
		if !strings.Contains(err.Error(), "token contains an invalid number of segments") &&
			!strings.Contains(err.Error(), "token is malformed") &&
			!strings.Contains(err.Error(), "illegal base64 data") { // для не-base64 частей
			t.Errorf("Expected malformed token error, got: %v", err)
		}
	})

	// 6. Ошибка валидации пустого токена
	t.Run("EmptyToken", func(t *testing.T) {
		_, err := service.ValidateToken("")
		if err == nil {
			t.Fatal("Expected error for empty token, but got nil")
		}
		// Ожидаем "token contains an invalid number of segments" или аналогичную ошибку
		if !strings.Contains(err.Error(), "token contains an invalid number of segments") {
			t.Errorf("Expected error for empty token (invalid segments), got: %v", err)
		}
	})
}
