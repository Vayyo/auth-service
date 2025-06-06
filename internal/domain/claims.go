package domain

import "github.com/golang-jwt/jwt/v5"

// Claims представляет собой структуру для хранения информации о пользователе в JWT-токене.
// Включает в себя имя пользователя и стандартные поля JWT-токена.
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}
