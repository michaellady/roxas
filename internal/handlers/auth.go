package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/mikelady/roxas/internal/auth"
)

// UserStore defines the interface for user database operations
type UserStore interface {
	CreateUser(ctx context.Context, email, passwordHash string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
}

// User represents a user in the system
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	GitHubID     *int64    `json:"github_id,omitempty"`
	GitHubLogin  *string   `json:"github_login,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ErrDuplicateEmail is returned when email already exists
var ErrDuplicateEmail = errors.New("email already registered")

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	store UserStore
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(store UserStore) *AuthHandler {
	return &AuthHandler{store: store}
}

// RegisterRequest represents the registration request body
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterResponse represents the registration response
type RegisterResponse struct {
	User  UserResponse `json:"user"`
	Token string       `json:"token"`
}

// UserResponse represents a user in API responses
type UserResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// ServeHTTP implements http.Handler
func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.Register(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// Register handles user registration POST /api/v1/auth/register
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate input
	if err := auth.ValidateRegistration(req.Email, req.Password); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Hash password
	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to process password")
		return
	}

	// Create user
	user, err := h.store.CreateUser(r.Context(), req.Email, passwordHash)
	if err != nil {
		if errors.Is(err, ErrDuplicateEmail) {
			h.writeError(w, http.StatusConflict, "email already registered")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Generate JWT token
	token, err := auth.GenerateToken(user.ID, user.Email)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	// Return response
	resp := RegisterResponse{
		User: UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			CreatedAt: user.CreatedAt.Format(time.RFC3339),
		},
		Token: token,
	}

	h.writeJSON(w, http.StatusCreated, resp)
}

// LoginRequest represents the login request body
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	User  UserResponse `json:"user"`
	Token string       `json:"token"`
}

// Login handles user login POST /api/v1/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate required fields
	if req.Email == "" {
		h.writeError(w, http.StatusBadRequest, "email is required")
		return
	}
	if req.Password == "" {
		h.writeError(w, http.StatusBadRequest, "password is required")
		return
	}

	// Look up user by email
	user, err := h.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to look up user")
		return
	}
	if user == nil {
		h.writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Verify password
	if !auth.CheckPassword(req.Password, user.PasswordHash) {
		h.writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Generate JWT token
	token, err := auth.GenerateToken(user.ID, user.Email)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	// Return response
	resp := LoginResponse{
		User: UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			CreatedAt: user.CreatedAt.Format(time.RFC3339),
		},
		Token: token,
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AuthHandler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, ErrorResponse{Error: message})
}
