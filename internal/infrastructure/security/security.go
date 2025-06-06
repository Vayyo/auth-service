package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params содержит параметры для хеширования Argon2.
// Вынесены в отдельную структуру для возможной конфигурации в будущем.
type Argon2Params struct {
	Time       uint32
	Memory     uint32
	Threads    uint8
	KeyLen     uint32
	SaltLength uint32 // Added SaltLength based on config.yaml
}

// DefaultArgon2Params возвращает параметры Argon2 по умолчанию.
// Эти значения теперь должны считываться из конфигурации,
// но для обратной совместимости или тестов можно оставить значения по умолчанию.
func DefaultArgon2Params() *Argon2Params {
	return &Argon2Params{
		Time:       3,     // Default value
		Memory:     65536, // Default value KiB
		Threads:    2,     // Default value
		KeyLen:     32,    // Default value bytes
		SaltLength: 16,    // Default value bytes
	}
}

// PasswordHasher реализует usecase.PasswordManager с использованием Argon2.
type PasswordHasher struct {
	params *Argon2Params
}

// NewPasswordHasher создает новый экземпляр PasswordHasher.
func NewPasswordHasher(params *Argon2Params) *PasswordHasher {
	if params == nil {
		params = DefaultArgon2Params()
	}
	return &PasswordHasher{params: params}
}

// Hash хеширует пароль с использованием Argon2.
// Формат хеша: argon2id$v=19$m=<memory>,t=<time>,p=<threads>$<salt_base64>$<hash_base64>.
func (ph *PasswordHasher) Hash(password string) (string, error) {
	salt := make([]byte, ph.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, ph.params.Time, ph.params.Memory, ph.params.Threads, ph.params.KeyLen)

	// Кодируем соль и хеш в base64.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Формируем строку в стандартном формате Argon2.
	// argon2id$v=19$m=65536,t=3,p=2$c2FsdF92YWx1ZQ$aGFzaF92YWx1ZQ.
	encodedHash := fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, ph.params.Memory, ph.params.Time, ph.params.Threads, b64Salt, b64Hash)

	return encodedHash, nil
}

// Verify проверяет, соответствует ли пароль хешу.
// Ожидает хеш в формате argon2id$v=19$m=<memory>,t=<time>,p=<threads>$<salt_base64>$<hash_base64>.
func (ph *PasswordHasher) Verify(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		// Неверный формат хеша.
		return false
	}

	var version int
	var memory, timeCost uint32
	var parallelism uint8

	_, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &memory, &timeCost, &parallelism)
	if err != nil {
		// Не удалось распарсить параметры.
		return false
	}
	_, err = fmt.Sscanf(parts[1], "v=%d", &version)
	if err != nil || version != argon2.Version {
		// Неверная версия Argon2.
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		// Не удалось декодировать соль.
		return false
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		// Не удалось декодировать хеш.
		return false
	}

	// Проверяем, совпадают ли параметры из хеша с текущими параметрами PasswordHasher
	// Это важно для безопасности: если параметры были изменены (усилены),
	// старые хеши все еще должны проверяться с теми параметрами, с которыми они были созданы.
	// Однако, для простоты, мы будем использовать параметры из самого хеша для сравнения.
	// В реальном приложении можно добавить логику для миграции хешей при изменении параметров.

	comparisonHash := argon2.IDKey([]byte(password), salt, timeCost, memory, parallelism, uint32(len(decodedHash)))

	return subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1
}
