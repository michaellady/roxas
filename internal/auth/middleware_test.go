package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testHandler is a simple handler that returns the user context values
func testHandler(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r.Context())
	email := GetEmailFromContext(r.Context())

	resp := map[string]string{
		"user_id": userID,
		"email":   email,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// TestMiddlewareValidToken tests that a valid JWT token allows the request through
// and makes user context available
func TestMiddlewareValidToken(t *testing.T) {
	// Generate a valid token
	userID := "user-123"
	email := "test@example.com"
	token, err := GenerateToken(userID, email)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Create request with valid Authorization header
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()

	// Wrap test handler with middleware
	handler := JWTMiddleware(http.HandlerFunc(testHandler))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	// Check that user context was set correctly
	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["user_id"] != userID {
		t.Errorf("Expected user_id %s, got %s", userID, resp["user_id"])
	}

	if resp["email"] != email {
		t.Errorf("Expected email %s, got %s", email, resp["email"])
	}
}

// TestMiddlewareMissingAuthorizationHeader tests that missing Authorization header returns 401
func TestMiddlewareMissingAuthorizationHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	// No Authorization header set

	rr := httptest.NewRecorder()

	handler := JWTMiddleware(http.HandlerFunc(testHandler))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d: %s", rr.Code, rr.Body.String())
	}

	// Check error message
	var errResp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errResp["error"] == "" {
		t.Error("Expected error message in response")
	}
}

// TestMiddlewareInvalidTokenFormat tests various invalid token formats return 401
func TestMiddlewareInvalidTokenFormat(t *testing.T) {
	testCases := []struct {
		name   string
		header string
	}{
		{"missing Bearer prefix", "invalid-token-no-bearer"},
		{"empty Bearer token", "Bearer "},
		{"Basic auth instead of Bearer", "Basic dXNlcjpwYXNz"},
		{"malformed JWT", "Bearer not.a.valid.jwt"},
		{"random string", "Bearer randomstring"},
		{"only Bearer keyword", "Bearer"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", tc.header)

			rr := httptest.NewRecorder()

			handler := JWTMiddleware(http.HandlerFunc(testHandler))
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("Expected status 401 Unauthorized for '%s', got %d: %s",
					tc.name, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestMiddlewareExpiredToken tests that an expired token returns 401
func TestMiddlewareExpiredToken(t *testing.T) {
	// Create an expired token manually
	claims := &Claims{
		UserID: "user-123",
		Email:  "test@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Expired 1 hour ago
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			Issuer:    "roxas",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JWTSecret)
	if err != nil {
		t.Fatalf("Failed to create expired token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	rr := httptest.NewRecorder()

	handler := JWTMiddleware(http.HandlerFunc(testHandler))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized for expired token, got %d: %s",
			rr.Code, rr.Body.String())
	}

	// Check that error message mentions expiration
	var errResp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if !strings.Contains(strings.ToLower(errResp["error"]), "expired") &&
		!strings.Contains(strings.ToLower(errResp["error"]), "token") {
		t.Errorf("Expected error message about expired token, got: %s", errResp["error"])
	}
}

// TestMiddlewareTamperedToken tests that a token signed with wrong secret returns 401
func TestMiddlewareTamperedToken(t *testing.T) {
	// Create a token signed with a different secret
	claims := &Claims{
		UserID: "user-123",
		Email:  "test@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "roxas",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	wrongSecret := []byte("wrong-secret-key")
	tokenString, err := token.SignedString(wrongSecret)
	if err != nil {
		t.Fatalf("Failed to create tampered token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	rr := httptest.NewRecorder()

	handler := JWTMiddleware(http.HandlerFunc(testHandler))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized for tampered token, got %d: %s",
			rr.Code, rr.Body.String())
	}

	// Check that error message is present
	var errResp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errResp["error"] == "" {
		t.Error("Expected error message in response")
	}
}

// TestMiddlewareContentType tests that error responses have JSON content type
func TestMiddlewareContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	// No Authorization header

	rr := httptest.NewRecorder()

	handler := JWTMiddleware(http.HandlerFunc(testHandler))
	handler.ServeHTTP(rr, req)

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}
}
