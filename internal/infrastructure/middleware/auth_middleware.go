package middleware

import (
	"auth-service/internal/usecase"
	"context"
	"net/http"
	"strings"
	//"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const UserIDKey contextKey = "userID"

// AuthMiddleware является middleware для аутентификации пользователей.
// Принимает jwtService в качестве аргумента для проверки JWT-токенов.
func AuthMiddleware(jwtService usecase.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			headerParts := strings.Split(authHeader, " ")
			if len(headerParts) != 2 || headerParts[0] != "Bearer" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			tokenString := headerParts[1]
			claims, err := jwtService.ValidateToken(tokenString)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserIDKey, claims.Username)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserNameFromContext извлекает имя пользователя из контекста.
// Возвращает имя пользователя и флаг, указывающий, существует ли имя пользователя.
func GetUserNameFromContext(ctx context.Context) (string, bool) {
	userName, ok := ctx.Value(UserIDKey).(string)
	return userName, ok
}
