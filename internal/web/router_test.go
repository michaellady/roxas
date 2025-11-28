package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mikelady/roxas/internal/handlers"
	"golang.org/x/crypto/bcrypt"
)

// =============================================================================
// Mock User Store for Web Tests
// =============================================================================

type MockUserStore struct {
	mu    sync.Mutex
	users map[string]*handlers.User
}

func NewMockUserStore() *MockUserStore {
	return &MockUserStore{users: make(map[string]*handlers.User)}
}

func (s *MockUserStore) CreateUser(ctx context.Context, email, passwordHash string) (*handlers.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Email == email {
			return nil, handlers.ErrDuplicateEmail
		}
	}
	user := &handlers.User{
		ID:           uuid.New().String(),
		Email:        email,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	s.users[user.ID] = user
	return user, nil
}

func (s *MockUserStore) GetUserByEmail(ctx context.Context, email string) (*handlers.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}

func hashPassword(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash)
}

// =============================================================================
// TB-WEB-01: Static file serving + base HTML template (TDD - RED)
// =============================================================================

func TestRouter_GetRoot_ReturnsHTML(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Should return HTML content type
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected Content-Type text/html, got %s", contentType)
	}

	// Should contain HTML doctype
	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Errorf("Expected HTML doctype, got: %s", body[:min(len(body), 100)])
	}

	// Should contain basic HTML structure
	if !strings.Contains(body, "<html") {
		t.Errorf("Expected <html> tag")
	}
	if !strings.Contains(body, "<head>") {
		t.Errorf("Expected <head> tag")
	}
	if !strings.Contains(body, "<body>") {
		t.Errorf("Expected <body> tag")
	}
}

func TestRouter_GetRoot_ContainsAppTitle(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	body := rr.Body.String()
	// Should contain app name in title
	if !strings.Contains(body, "Roxas") {
		t.Errorf("Expected 'Roxas' in page content")
	}
}

func TestRouter_GetStatic_ServesCSS(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/static/css/style.css", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Should return CSS content type
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/css") {
		t.Errorf("Expected Content-Type text/css, got %s", contentType)
	}
}

func TestRouter_GetLogin_ReturnsLoginPage(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "login") && !strings.Contains(body, "Login") {
		t.Errorf("Expected login form content")
	}
}

func TestRouter_GetSignup_ReturnsSignupPage(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/signup", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "signup") && !strings.Contains(body, "Sign") {
		t.Errorf("Expected signup form content")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// =============================================================================
// TB-WEB-03: Web login page (TDD)
// =============================================================================

func TestRouter_PostLogin_ValidCredentials_SetsCookieAndRedirects(t *testing.T) {
	// Create a user store with a test user
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	// First register a user
	userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// POST login form
	form := url.Values{}
	form.Set("email", "test@example.com")
	form.Set("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to dashboard
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303 See Other, got %d: %s", rr.Code, rr.Body.String())
	}

	location := rr.Header().Get("Location")
	if location != "/dashboard" {
		t.Errorf("Expected redirect to /dashboard, got %s", location)
	}

	// Should set auth_token cookie
	cookies := rr.Result().Cookies()
	var authCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "auth_token" {
			authCookie = c
			break
		}
	}

	if authCookie == nil {
		t.Error("Expected auth_token cookie to be set")
	} else {
		if !authCookie.HttpOnly {
			t.Error("Expected cookie to be HttpOnly")
		}
		if authCookie.Value == "" {
			t.Error("Expected cookie to have a value")
		}
	}
}

func TestRouter_PostLogin_InvalidCredentials_ShowsError(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	// Register a user
	userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// POST with wrong password
	form := url.Values{}
	form.Set("email", "test@example.com")
	form.Set("password", "wrongpassword")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 200 with login page showing error
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	// Should show error message (not reveal which field is wrong)
	if !strings.Contains(strings.ToLower(body), "invalid") &&
		!strings.Contains(strings.ToLower(body), "error") &&
		!strings.Contains(strings.ToLower(body), "incorrect") {
		t.Errorf("Expected error message in response")
	}
}

func TestRouter_PostLogin_NonexistentUser_ShowsError(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	// POST with non-existent user
	form := url.Values{}
	form.Set("email", "noone@example.com")
	form.Set("password", "anypassword")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 200 with login page showing error
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Should NOT set auth cookie
	cookies := rr.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "auth_token" && c.Value != "" {
			t.Error("Should not set auth cookie for failed login")
		}
	}
}
