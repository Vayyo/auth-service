package configs

type Config struct {
	Server   ServerConfig
	Postgres PostgresConfig
	JWT      JWTConfig
	Logger   LoggerConfig
	CORS     CORSConfig
}

type ServerConfig struct {
	Host string
	Port string
	// RT - Время на чтение одного запроса.
	// WT - Время на ответ для одного запроса.
	// Время ограничено, чтобы не тратить ресурсы сервера.
	// Бывают ситуации, когда клиент забывает закрыть соединение,
	// тогда сущетствует RT, чтобы разорвать соединение
	// и не нагружать сервер.
	ReadTimeout  int
	WriteTimeout int
}

type PostgresConfig struct {
	Host     string
	Port     string
	Password string
	User     string
	DBName   string
}

type JWTConfig struct {
	SecretKey  string
	AccessTTL  int // Время жизни access - токена.
	RefreshTTL int // Время жизни refresh - токена.
}

type LoggerConfig struct {
	Level string // Уровень логгирования info, debug, error.
	// Уровни логирования позволяют работать с разной информацией.
	// В зависимости от уровня, мы получаем соответствующий тип информации.
	// Для уровня info характерна базовая информация о работе проекта, подходит для прода.
	// Для уровня debug характерна подробная информация, подходит для разработки.
	// Для уровня error характерна информация об ошибках, мешающих выполнению программы.
	Format string // Формат логирования json/console.
}

// Cross-Origin Resource Sharing (CORS) - Механизм,
// использующий дополнительные HTTP - заголовки,
// позволяющие пользователю получить определенный контент,
// доступный на другом источнике этого домена.
// CORS используется в качестве контроля доступа,
// Защиты, прозрачности и предсказуемости.
// Используем только те заголовки, методы и источники,
// которые нужно.
type CORSConfig struct {
	AllowedHeaders []string
	AllowedMethods []string
	AllowedOrigins []string
}
