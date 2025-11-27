package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// MockUserStore is an in-memory implementation of UserStore for testing
type MockUserStore struct {
	mu    sync.Mutex
	users map[string]*User
}

// NewMockUserStore creates a new mock user store
func NewMockUserStore() *MockUserStore {
	return &MockUserStore{
		users: make(map[string]*User),
	}
}

// CreateUser creates a new user in the mock store
func (m *MockUserStore) CreateUser(ctx context.Context, email, passwordHash string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicate email
	for _, u := range m.users {
		if u.Email == email {
			return nil, ErrDuplicateEmail
		}
	}

	user := &User{
		ID:           uuid.New().String(),
		Email:        email,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	m.users[user.ID] = user
	return user, nil
}

// GetUserByEmail retrieves a user by email
func (m *MockUserStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}

// TestRegisterValidUser tests successful registration with valid credentials
func TestRegisterValidUser(t *testing.T) {
	store := NewMockUserStore()
	handler := NewAuthHandler(store)

	reqBody := map[string]string{
		"email":    "test@example.com",
		"password": "securepassword123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status 201 Created, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp RegisterResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.User.Email != reqBody["email"] {
		t.Errorf("Expected email %s, got %s", reqBody["email"], resp.User.Email)
	}

	if resp.User.ID == "" {
		t.Error("Expected user ID to be set")
	}

	if resp.Token == "" {
		t.Error("Expected JWT token to be returned")
	}

	// Token should be a valid JWT format (three dot-separated parts)
	parts := strings.Split(resp.Token, ".")
	if len(parts) != 3 {
		t.Errorf("Expected JWT with 3 parts, got %d parts", len(parts))
	}
}

// TestRegisterDuplicateEmail tests that duplicate email returns 409 Conflict
func TestRegisterDuplicateEmail(t *testing.T) {
	store := NewMockUserStore()
	handler := NewAuthHandler(store)

	// First registration
	reqBody := map[string]string{
		"email":    "duplicate@example.com",
		"password": "securepassword123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("First registration failed: %d: %s", rr.Code, rr.Body.String())
	}

	// Second registration with same email
	body2, _ := json.Marshal(reqBody)
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")

	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusConflict {
		t.Errorf("Expected status 409 Conflict for duplicate email, got %d", rr2.Code)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr2.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errResp.Error == "" {
		t.Error("Expected error message in response")
	}
}

// TestRegisterInvalidEmail tests that invalid email format returns 400 Bad Request
func TestRegisterInvalidEmail(t *testing.T) {
	store := NewMockUserStore()
	handler := NewAuthHandler(store)

	testCases := []struct {
		name  string
		email string
	}{
		{"missing @", "invalidemail.com"},
		{"missing domain", "invalid@"},
		{"missing local part", "@example.com"},
		{"spaces in email", "invalid email@example.com"},
		{"empty email", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := map[string]string{
				"email":    tc.email,
				"password": "securepassword123",
			}
			body, _ := json.Marshal(reqBody)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400 Bad Request for email '%s', got %d", tc.email, rr.Code)
			}
		})
	}
}

// TestRegisterWeakPassword tests that weak passwords return 400 Bad Request
func TestRegisterWeakPassword(t *testing.T) {
	store := NewMockUserStore()
	handler := NewAuthHandler(store)

	testCases := []struct {
		name     string
		password string
	}{
		{"too short (7 chars)", "1234567"},
		{"too short (1 char)", "a"},
		{"empty password", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := map[string]string{
				"email":    "test@example.com",
				"password": tc.password,
			}
			body, _ := json.Marshal(reqBody)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400 Bad Request for password '%s', got %d", tc.password, rr.Code)
			}
		})
	}
}

// TestRegisterMissingFields tests that missing required fields return 400 Bad Request
func TestRegisterMissingFields(t *testing.T) {
	store := NewMockUserStore()
	handler := NewAuthHandler(store)

	testCases := []struct {
		name string
		body string
	}{
		{"missing email", `{"password": "securepassword123"}`},
		{"missing password", `{"email": "test@example.com"}`},
		{"empty body", `{}`},
		{"invalid JSON", `{invalid}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400 Bad Request for %s, got %d: %s", tc.name, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestRegisterReturnsCorrectContentType tests that response has JSON content type
func TestRegisterReturnsCorrectContentType(t *testing.T) {
	store := NewMockUserStore()
	handler := NewAuthHandler(store)

	reqBody := map[string]string{
		"email":    "contenttype@example.com",
		"password": "securepassword123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}
}
