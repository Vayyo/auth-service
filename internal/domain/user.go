package domain

import "time"

// Про слой domain.
// В слое domain определяются структуры, и, возможно интерфейсы,
// С которыми происходит взаимодействие в остальных слоях.
// Также интерфейсы для работы со структурами можно переместить
// в usecase/ports.go.

type User struct {
	ID             uint
	Name           string
	HashedPassword string
	Email          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	IsActive       bool
	//Roles          []Role
}

type UserUpdate struct {
	ID       uint
	Name     *string
	Email    *string
	Password *string
}

// Сессия пользователя.
// Содержит информацию о сессии пользователя,
// включая IP-адрес, User-Agent, токен обновления и время создания/обновления.
// Используется для аутентификации и авторизации пользователей.
type UserSession struct {
	ID               uint
	UserID           uint
	IP               string
	UserAgent        string
	RefreshTokenHash string
	ExpiresAt        time.Time
	CreatedAt        time.Time
	IsActive         bool
}
