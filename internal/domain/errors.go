package domain

import "errors"

// Определения стандартных ошибок для доменного слоя.
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrRoleNotFound       = errors.New("role not found")
	ErrPermissionNotFound = errors.New("permission not found")

	ErrEmailTaken         = errors.New("email is already taken")
	ErrUsernameTaken      = errors.New("username is already taken") // Если будет проверка уникальности имени пользователя.
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrRepository         = errors.New("repository error")   // Общая ошибка репозитория.
	ErrValidation         = errors.New("validation error")   // Общая ошибка валидации.
	ErrConflict           = errors.New("resource conflict")  // Ошибка конфликта (например, уже существует).
	ErrPermissionDenied   = errors.New("permission denied")  // Ошибка доступа.
	ErrBadRequest         = errors.New("bad request")        // Общая ошибка некорректного запроса.
	ErrUnauthenticated    = errors.New("unauthenticated")    // Ошибка "не аутентифицирован".
	ErrNotFound           = errors.New("resource not found") // Общая ошибка "не найдено", если не уточнено.
	ErrRoleConflict       = errors.New("role conflict")      // Ошибка конфликта для ролей.
)
