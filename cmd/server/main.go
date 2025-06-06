package main

import (
	"auth-service/internal/repository"
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	pool, err := pgxpool.New(context.Background(), "postgres://user:password@localhost:5432/auth_service")
	if err != nil {
		panic("Unable to connect to database: " + err.Error())
	}

	userRepo := repository.NewUserRepository(nil, nil)
}
