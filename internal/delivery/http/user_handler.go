package http

import (
	"auth-service/internal/domain"
	"auth-service/internal/usecase"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
)

// Про слой Delivery.
// Слой доставки служит для реализации HTTP - обработчиков, использующих
// методы из реализации слоя usecase.

type UserHandler struct {
	uc usecase.UserUseCase
}

func NewUserHandler(uc usecase.UserUseCase) *UserHandler {
	return &UserHandler{
		uc: uc,
	}
}

// Хэндлер HTTP - регистрации пользователя.
// Использует обработчик пользователя *UserHandler
// для доступа к операциям БД.
// Использует writer для работы через структуру и request для обработки запроса.
func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Создаем структуру запроса, для того, чтобы потом в нее записать тело запроса (r.Body)
	// Обязательно используем JSON - ключи, чтобы Декодер правильно распознал структуру.
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	// Присваиваем ошибке новый JSON декодер. Декодер принимает на вход тело запроса (r.Body)
	// И производит его декодирование и запись в структуру req.
	// В случае ошибки, происходит ответ на запрос, в который передается ошибка и статус ответа.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// В случае если все прошло успешно, происходит обращение к базе данных, через интерфейс
	// для регистрации пользователя по данным из структуры req, также передается контекст.
	// Контекст к примеру, нужен чтобы отменять слишком долгие запросы.
	// В случае если ошибки не произошло, создается новая структура resp,
	// в которую помещаются данные с переменной user, полученные от БД.
	// Затем выставляется заголовок для ответа, и с помощью Encoder'a
	// производится запись в тело ответа, куда помещаются ID, Email и Token.
	ip := getIP(r)
	userAgent := r.Header.Get("User-Agent")
	user, accessToken, refreshToken, err := h.uc.Register(r.Context(), req.Name, req.Email, req.Password, ip, userAgent)
	if err != nil {
		// Здесь можно добавить более гранулированную обработку ошибок
		if errors.Is(err, domain.ErrEmailTaken) || errors.Is(err, domain.ErrUsernameTaken) {
			http.Error(w, err.Error(), http.StatusConflict)
		} else if strings.Contains(err.Error(), "validation error") {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}
	resp := struct {
		ID           uint   `json:"id"`
		Name         string `json:"name"`
		Email        string `json:"email"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{
		ID:           user.ID,
		Name:         user.Name,
		Email:        user.Email,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	ip := getIP(r)
	userAgent := r.Header.Get("User-Agent")
	user, accessToken, refreshToken, err := h.uc.Login(r.Context(), req.Email, req.Password, ip, userAgent)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}
	resp := struct {
		ID           uint   `json:"id"`
		Name         string `json:"name"`
		Email        string `json:"email"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{
		ID:           user.ID,
		Name:         user.Name,
		Email:        user.Email,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (h *UserHandler) Update(w http.ResponseWriter, r *http.Request) {
	// .
	var req struct {
		ID       uint    `json:"id"`
		Name     *string `json:"name,omitempty"`
		Email    *string `json:"email,omitempty"`
		Password *string `json:"password,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userUpdate := &domain.UserUpdate{
		ID:       req.ID,
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	}
	if err := h.uc.Update(r.Context(), userUpdate); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) Deactivate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID uint `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.uc.Deactivate(r.Context(), req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) Activate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID uint `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.uc.Activate(r.Context(), req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getIP получает IP-адрес из запроса, учитывая прокси.
func getIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// X-Forwarded-For может содержать список IP: "client, proxy1, proxy2"
		// Нам нужен самый первый (клиентский)
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Если не удалось разделить, возможно, порт отсутствует (например, в тестах)
		return r.RemoteAddr
	}
	return ip
}
