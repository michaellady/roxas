package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// RegisterRequest represents the registration request body
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterResponse represents the expected registration response
type RegisterResponse struct {
	User  UserResponse `json:"user"`
	Token string       `json:"token"`
}

// UserResponse represents the user object in responses
type UserResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// TestRegisterValidUser tests successful registration with valid credentials
func TestRegisterValidUser(t *testing.T) {
	handler := NewAuthHandler(nil) // Will need DB dependency

	reqBody := RegisterRequest{
		Email:    "test@example.com",
		Password: "securepassword123",
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

	if resp.User.Email != reqBody.Email {
		t.Errorf("Expected email %s, got %s", reqBody.Email, resp.User.Email)
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
	handler := NewAuthHandler(nil) // Will need DB dependency

	// First registration
	reqBody := RegisterRequest{
		Email:    "duplicate@example.com",
		Password: "securepassword123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("First registration failed: %d", rr.Code)
	}

	// Second registration with same email
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
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
	handler := NewAuthHandler(nil)

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
			reqBody := RegisterRequest{
				Email:    tc.email,
				Password: "securepassword123",
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
	handler := NewAuthHandler(nil)

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
			reqBody := RegisterRequest{
				Email:    "test@example.com",
				Password: tc.password,
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
	handler := NewAuthHandler(nil)

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
				t.Errorf("Expected status 400 Bad Request for %s, got %d", tc.name, rr.Code)
			}
		})
	}
}

// TestRegisterReturnsCorrectContentType tests that response has JSON content type
func TestRegisterReturnsCorrectContentType(t *testing.T) {
	handler := NewAuthHandler(nil)

	reqBody := RegisterRequest{
		Email:    "contenttype@example.com",
		Password: "securepassword123",
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
