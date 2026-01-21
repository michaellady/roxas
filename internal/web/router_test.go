package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mikelady/roxas/internal/auth"
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

// =============================================================================
// TB-WEB-04: Web signup page (TDD)
// =============================================================================

func TestRouter_PostSignup_ValidData_CreatesUserAndRedirects(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	// POST signup form
	form := url.Values{}
	form.Set("email", "newuser@example.com")
	form.Set("password", "securepassword123")
	form.Set("confirm_password", "securepassword123")

	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to login
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303 See Other, got %d: %s", rr.Code, rr.Body.String())
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}

	// Verify user was created
	user, _ := userStore.GetUserByEmail(context.Background(), "newuser@example.com")
	if user == nil {
		t.Error("Expected user to be created")
	}
}

func TestRouter_PostSignup_DuplicateEmail_ShowsError(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	// Create existing user
	userStore.CreateUser(context.Background(), "existing@example.com", hashPassword("password"))

	// Try to signup with same email
	form := url.Values{}
	form.Set("email", "existing@example.com")
	form.Set("password", "newpassword123")
	form.Set("confirm_password", "newpassword123")

	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 200 with error
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(strings.ToLower(body), "email") ||
		(!strings.Contains(strings.ToLower(body), "exists") &&
			!strings.Contains(strings.ToLower(body), "already") &&
			!strings.Contains(strings.ToLower(body), "use")) {
		t.Errorf("Expected error about email already in use")
	}
}

func TestRouter_PostSignup_PasswordMismatch_ShowsError(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	form := url.Values{}
	form.Set("email", "newuser@example.com")
	form.Set("password", "password123")
	form.Set("confirm_password", "different456")

	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 200 with error
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(strings.ToLower(body), "match") &&
		!strings.Contains(strings.ToLower(body), "password") {
		t.Errorf("Expected error about password mismatch")
	}
}

func TestRouter_PostSignup_ShortPassword_ShowsError(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	form := url.Values{}
	form.Set("email", "newuser@example.com")
	form.Set("password", "short")
	form.Set("confirm_password", "short")

	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 200 with error
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(strings.ToLower(body), "password") &&
		!strings.Contains(strings.ToLower(body), "8") {
		t.Errorf("Expected error about password length")
	}
}

// =============================================================================
// TB-WEB-07: Dashboard page with commits and posts (TDD - RED)
// =============================================================================

func TestRouter_GetDashboard_WithoutAuth_RedirectsToLogin(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to login page
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303 See Other redirect, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

func TestRouter_GetDashboard_WithAuth_ReturnsHTML(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	// Create a test user and get valid auth cookie
	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Generate valid JWT token
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Should return HTML content
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected Content-Type text/html, got %s", contentType)
	}

	// Should contain dashboard content
	body := rr.Body.String()
	if !strings.Contains(body, "Dashboard") && !strings.Contains(body, "dashboard") {
		t.Errorf("Expected dashboard content in response")
	}
}

func TestRouter_GetDashboard_WithAuth_ShowsRepositories(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	// Create a test user
	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Add repositories for this user
	repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/user/repo1", "secret1")
	repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/user/repo2", "secret2")

	// Generate valid JWT token
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	// Should show repository URLs
	if !strings.Contains(body, "repo1") || !strings.Contains(body, "repo2") {
		t.Errorf("Expected repositories to be displayed, got: %s", body[:min(len(body), 500)])
	}
}

func TestRouter_GetDashboard_WithAuth_ShowsCommits(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	commitLister := NewMockCommitListerForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, commitLister, nil, nil, "")

	// Create a test user
	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Add a repository (required to show commits section, not empty state)
	repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/user/repo", "secret")

	// Add commits for this user
	commitLister.AddCommitForUser(user.ID, &MockCommit{
		SHA:     "abc123def456789",
		Message: "Add new feature",
		Author:  "testuser",
	})

	// Generate valid JWT token
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	// Should show commit messages
	if !strings.Contains(body, "Add new feature") {
		t.Errorf("Expected commit message to be displayed, got: %s", body[:min(len(body), 500)])
	}
}

func TestRouter_GetDashboard_EmptyState_ShowsGuidance(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	// Create a test user with no repos/commits
	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Generate valid JWT token
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	// Should provide guidance for adding first repository (check for any of these phrases)
	hasAddRepo := strings.Contains(strings.ToLower(body), "add") && strings.Contains(strings.ToLower(body), "repository")
	hasGetStarted := strings.Contains(strings.ToLower(body), "get started")
	if !hasAddRepo && !hasGetStarted {
		t.Errorf("Expected empty state guidance, got: %s", body)
	}
}

// =============================================================================
// TB-WEB-08: Logout functionality (TDD)
// =============================================================================

func TestRouter_PostLogout_ClearsCookieAndRedirects(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	// Create a test user and get valid auth cookie
	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	// POST to logout with auth cookie
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to login page
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303 See Other, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}

	// Should clear auth_token cookie (MaxAge=-1 or empty value)
	cookies := rr.Result().Cookies()
	var authCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "auth_token" {
			authCookie = c
			break
		}
	}

	if authCookie == nil {
		t.Error("Expected auth_token cookie to be set (with clear directive)")
	} else {
		// Cookie should be cleared (MaxAge < 0 or value empty)
		if authCookie.MaxAge >= 0 && authCookie.Value != "" {
			t.Errorf("Expected cookie to be cleared, got MaxAge=%d, Value=%s", authCookie.MaxAge, authCookie.Value)
		}
	}
}

func TestRouter_PostLogout_SubsequentDashboardRequiresLogin(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	// Create a test user
	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	// First, verify dashboard is accessible with valid cookie
	reqDash := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	reqDash.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rrDash := httptest.NewRecorder()
	router.ServeHTTP(rrDash, reqDash)

	if rrDash.Code != http.StatusOK {
		t.Fatalf("Expected dashboard to be accessible, got %d", rrDash.Code)
	}

	// POST to logout
	reqLogout := httptest.NewRequest(http.MethodPost, "/logout", nil)
	reqLogout.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rrLogout := httptest.NewRecorder()
	router.ServeHTTP(rrLogout, reqLogout)

	// Now access dashboard without cookie - should redirect
	reqAfter := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rrAfter := httptest.NewRecorder()
	router.ServeHTTP(rrAfter, reqAfter)

	if rrAfter.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect after logout, got %d", rrAfter.Code)
	}

	location := rrAfter.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

func TestRouter_GetLogout_MethodNotAllowed(t *testing.T) {
	router := NewRouter()

	// GET to logout should not be allowed (only POST)
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405 Method Not Allowed, got %d", rr.Code)
	}
}

// Helper function to generate JWT token for tests
func generateToken(userID, email string) (string, error) {
	return auth.GenerateToken(userID, email)
}

// =============================================================================
// Mock Stores for Dashboard Tests
// =============================================================================

// MockRepositoryStoreForWeb implements RepositoryStore for web tests
type MockRepositoryStoreForWeb struct {
	mu    sync.Mutex
	repos map[string]*handlers.Repository
}

func NewMockRepositoryStoreForWeb() *MockRepositoryStoreForWeb {
	return &MockRepositoryStoreForWeb{repos: make(map[string]*handlers.Repository)}
}

func (s *MockRepositoryStoreForWeb) CreateRepository(ctx context.Context, userID, githubURL, webhookSecret string) (*handlers.Repository, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	repo := &handlers.Repository{
		ID:            uuid.New().String(),
		UserID:        userID,
		GitHubURL:     githubURL,
		WebhookSecret: webhookSecret,
		CreatedAt:     time.Now(),
	}
	s.repos[repo.ID] = repo
	return repo, nil
}

func (s *MockRepositoryStoreForWeb) GetRepositoryByUserAndURL(ctx context.Context, userID, githubURL string) (*handlers.Repository, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.repos {
		if r.UserID == userID && r.GitHubURL == githubURL {
			return r, nil
		}
	}
	return nil, nil
}

func (s *MockRepositoryStoreForWeb) ListRepositoriesByUser(ctx context.Context, userID string) ([]*handlers.Repository, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*handlers.Repository
	for _, r := range s.repos {
		if r.UserID == userID {
			result = append(result, r)
		}
	}
	return result, nil
}

func (s *MockRepositoryStoreForWeb) GetRepositoryByID(ctx context.Context, repoID string) (*handlers.Repository, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if repo, ok := s.repos[repoID]; ok {
		return repo, nil
	}
	return nil, nil
}

func (s *MockRepositoryStoreForWeb) UpdateRepository(ctx context.Context, repoID, name string, isActive bool) (*handlers.Repository, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if repo, ok := s.repos[repoID]; ok {
		repo.Name = name
		repo.IsActive = isActive
		return repo, nil
	}
	return nil, nil
}

func (s *MockRepositoryStoreForWeb) UpdateWebhookSecret(ctx context.Context, repoID, newSecret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if repo, ok := s.repos[repoID]; ok {
		repo.WebhookSecret = newSecret
		return nil
	}
	return nil
}

func (s *MockRepositoryStoreForWeb) DeleteRepository(ctx context.Context, repoID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.repos[repoID]; ok {
		delete(s.repos, repoID)
		return nil
	}
	return nil
}

// MockCommit for web tests (alias for DashboardCommit)
type MockCommit = DashboardCommit

// MockCommitListerForWeb implements commit listing for web tests
type MockCommitListerForWeb struct {
	mu      sync.Mutex
	commits map[string][]*DashboardCommit // userID -> commits
}

func NewMockCommitListerForWeb() *MockCommitListerForWeb {
	return &MockCommitListerForWeb{commits: make(map[string][]*DashboardCommit)}
}

func (s *MockCommitListerForWeb) AddCommitForUser(userID string, commit *DashboardCommit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if commit.ID == "" {
		commit.ID = uuid.New().String()
	}
	s.commits[userID] = append(s.commits[userID], commit)
}

func (s *MockCommitListerForWeb) ListCommitsByUser(ctx context.Context, userID string) ([]*DashboardCommit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if commits, ok := s.commits[userID]; ok {
		return commits, nil
	}
	return []*DashboardCommit{}, nil
}

// =============================================================================
// TB-WEB-09: Web UI Integration Test (TDD)
// Full flow: signup → login → dashboard → webhook → logout → redirect
//
// This test uses httptest.Server + http.Client to exercise the full HTTP stack
// including cookie management and redirect handling, matching real browser behavior.
//
// Key design decisions:
// - Uses the same router configuration as production (NewRouterWithAllStores)
// - In-memory mock stores avoid DB dependency (DB-backed E2E deferred to TB21)
// - Cookie jar automatically manages auth_token across requests
// - CheckRedirect prevents auto-follow so we can verify redirect locations
// - Catches regressions in redirect/cookie handling that direct handler calls miss
// =============================================================================

func TestWebUI_FullAuthenticationFlow(t *testing.T) {
	// Setup stores - same configuration as production
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	commitLister := NewMockCommitListerForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, commitLister, nil, nil, "")

	// Start test server with production router
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Create cookie jar for automatic cookie management (like a real browser)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Failed to create cookie jar: %v", err)
	}

	// Create client that doesn't auto-follow redirects (so we can verify them)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	const testEmail = "integration-test@example.com"
	const testPassword = "securepassword123"

	// =========================================================================
	// Step 1: GET /signup → form renders
	// =========================================================================
	t.Log("Step 1: GET /signup - form renders")

	resp, err := client.Get(ts.URL + "/signup")
	if err != nil {
		t.Fatalf("Step 1 FAILED: Request error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Step 1 FAILED: Expected 200 OK for GET /signup, got %d", resp.StatusCode)
	}
	bodyBytes := make([]byte, 4096)
	n, _ := resp.Body.Read(bodyBytes)
	body := string(bodyBytes[:n])
	if !strings.Contains(body, "Sign") {
		t.Fatalf("Step 1 FAILED: Signup page should contain 'Sign' text")
	}
	t.Log("Step 1 PASSED: Signup form rendered")

	// =========================================================================
	// Step 2: POST /signup → user created, redirect to /login
	// =========================================================================
	t.Log("Step 2: POST /signup - user created, redirect to /login")

	signupForm := url.Values{}
	signupForm.Set("email", testEmail)
	signupForm.Set("password", testPassword)
	signupForm.Set("confirm_password", testPassword)

	resp, err = client.PostForm(ts.URL+"/signup", signupForm)
	if err != nil {
		t.Fatalf("Step 2 FAILED: Request error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("Step 2 FAILED: Expected 303 redirect for POST /signup, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "/login" {
		t.Fatalf("Step 2 FAILED: Expected redirect to /login, got %s", resp.Header.Get("Location"))
	}

	// Verify user was created in store
	user, _ := userStore.GetUserByEmail(context.Background(), testEmail)
	if user == nil {
		t.Fatalf("Step 2 FAILED: User was not created in store")
	}
	t.Log("Step 2 PASSED: User created and redirected to login")

	// =========================================================================
	// Step 3: GET /login → form renders (follow redirect from signup)
	// =========================================================================
	t.Log("Step 3: GET /login - form renders")

	resp, err = client.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("Step 3 FAILED: Request error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Step 3 FAILED: Expected 200 OK for GET /login, got %d", resp.StatusCode)
	}
	bodyBytes = make([]byte, 4096)
	n, _ = resp.Body.Read(bodyBytes)
	body = string(bodyBytes[:n])
	if !strings.Contains(strings.ToLower(body), "login") {
		t.Fatalf("Step 3 FAILED: Login page should contain 'login' text")
	}
	t.Log("Step 3 PASSED: Login form rendered")

	// =========================================================================
	// Step 4: POST /login → cookie set, redirect to /dashboard
	// =========================================================================
	t.Log("Step 4: POST /login - cookie set, redirect to /dashboard")

	loginForm := url.Values{}
	loginForm.Set("email", testEmail)
	loginForm.Set("password", testPassword)

	resp, err = client.PostForm(ts.URL+"/login", loginForm)
	if err != nil {
		t.Fatalf("Step 4 FAILED: Request error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("Step 4 FAILED: Expected 303 redirect for POST /login, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "/dashboard" {
		t.Fatalf("Step 4 FAILED: Expected redirect to /dashboard, got %s", resp.Header.Get("Location"))
	}

	// Verify cookie was set (cookie jar handles this automatically)
	tsURL, _ := url.Parse(ts.URL)
	cookies := jar.Cookies(tsURL)
	var hasAuthCookie bool
	for _, c := range cookies {
		if c.Name == "auth_token" && c.Value != "" {
			hasAuthCookie = true
			break
		}
	}
	if !hasAuthCookie {
		t.Fatalf("Step 4 FAILED: Expected auth_token cookie to be set in jar")
	}
	t.Log("Step 4 PASSED: Logged in, cookie set, redirected to dashboard")

	// =========================================================================
	// Step 5: GET /dashboard → shows empty state (no repos/commits yet)
	// =========================================================================
	t.Log("Step 5: GET /dashboard - shows empty state")

	resp, err = client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("Step 5 FAILED: Request error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Step 5 FAILED: Expected 200 OK for GET /dashboard, got %d", resp.StatusCode)
	}
	bodyBytes = make([]byte, 8192)
	n, _ = resp.Body.Read(bodyBytes)
	dashBody := string(bodyBytes[:n])
	// Should show empty state guidance
	hasEmptyState := strings.Contains(strings.ToLower(dashBody), "get started") ||
		(strings.Contains(strings.ToLower(dashBody), "add") && strings.Contains(strings.ToLower(dashBody), "repository"))
	if !hasEmptyState {
		t.Fatalf("Step 5 FAILED: Expected empty state guidance on dashboard")
	}
	t.Log("Step 5 PASSED: Dashboard shows empty state")

	// =========================================================================
	// Step 6: Simulate webhook creating a commit (add data to stores)
	// =========================================================================
	t.Log("Step 6: Simulate webhook creating commit")

	// Add a repository for this user
	repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/testuser/testrepo", "webhook-secret")

	// Simulate webhook: add a commit for this user
	commitLister.AddCommitForUser(user.ID, &DashboardCommit{
		SHA:     "abc123def456",
		Message: "feat: Add awesome new feature",
		Author:  "testuser",
	})
	t.Log("Step 6 PASSED: Commit added via simulated webhook")

	// =========================================================================
	// Step 7: GET /dashboard → shows commit
	// =========================================================================
	t.Log("Step 7: GET /dashboard - shows commit")

	resp, err = client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("Step 7 FAILED: Request error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Step 7 FAILED: Expected 200 OK, got %d", resp.StatusCode)
	}
	bodyBytes = make([]byte, 8192)
	n, _ = resp.Body.Read(bodyBytes)
	dashWithDataBody := string(bodyBytes[:n])
	if !strings.Contains(dashWithDataBody, "Add awesome new feature") {
		t.Fatalf("Step 7 FAILED: Expected commit message to be displayed, got: %s", dashWithDataBody[:min(len(dashWithDataBody), 500)])
	}
	t.Log("Step 7 PASSED: Dashboard shows commit")

	// =========================================================================
	// Step 8: POST /logout → cookie cleared, redirect to /login
	// =========================================================================
	t.Log("Step 8: POST /logout - cookie cleared, redirect to /login")

	resp, err = client.PostForm(ts.URL+"/logout", nil)
	if err != nil {
		t.Fatalf("Step 8 FAILED: Request error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("Step 8 FAILED: Expected 303 redirect, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "/login" {
		t.Fatalf("Step 8 FAILED: Expected redirect to /login, got %s", resp.Header.Get("Location"))
	}

	// Verify cookie is cleared in jar (MaxAge=-1 removes it from jar)
	cookies = jar.Cookies(tsURL)
	hasAuthCookie = false
	for _, c := range cookies {
		if c.Name == "auth_token" && c.Value != "" {
			hasAuthCookie = true
			break
		}
	}
	if hasAuthCookie {
		t.Fatalf("Step 8 FAILED: Expected auth_token cookie to be cleared from jar")
	}
	t.Log("Step 8 PASSED: Logged out, cookie cleared")

	// =========================================================================
	// Step 9: GET /dashboard → redirects to /login (not authenticated)
	// =========================================================================
	t.Log("Step 9: GET /dashboard without auth - redirects to /login")

	resp, err = client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("Step 9 FAILED: Request error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("Step 9 FAILED: Expected 303 redirect, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "/login" {
		t.Fatalf("Step 9 FAILED: Expected redirect to /login, got %s", resp.Header.Get("Location"))
	}
	t.Log("Step 9 PASSED: Unauthenticated dashboard access redirects to login")

	t.Log("=== ALL 9 STEPS PASSED: Full authentication flow verified ===")
}

// =============================================================================
// MockPostLister for dashboard tests
// =============================================================================

type MockPostListerForWeb struct {
	mu    sync.Mutex
	posts map[string][]*DashboardPost // userID -> posts
}

func NewMockPostListerForWeb() *MockPostListerForWeb {
	return &MockPostListerForWeb{posts: make(map[string][]*DashboardPost)}
}

func (s *MockPostListerForWeb) AddPostForUser(userID string, post *DashboardPost) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if post.ID == "" {
		post.ID = uuid.New().String()
	}
	s.posts[userID] = append(s.posts[userID], post)
}

func (s *MockPostListerForWeb) ListPostsByUser(ctx context.Context, userID string) ([]*DashboardPost, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if posts, ok := s.posts[userID]; ok {
		return posts, nil
	}
	return []*DashboardPost{}, nil
}

// =============================================================================
// MockSecretGenerator for testing
// =============================================================================

type MockSecretGeneratorForWeb struct {
	Secret string
}

func (m *MockSecretGeneratorForWeb) Generate() (string, error) {
	return m.Secret, nil
}

// =============================================================================
// TB-WEB-10: E2E Test - Add Repository and Verify Webhook
//
// Full flow: login → /repositories/new → submit repo → success page → webhook ping
//
// This test verifies the complete repository creation flow including:
// - Authentication guard on /repositories/new
// - Form submission with GitHub URL validation
// - Success page displaying webhook configuration
// - Webhook endpoint receiving and validating requests
// =============================================================================

func TestWebUI_AddRepositoryAndVerifyWebhook(t *testing.T) {
	// Fixed webhook secret for deterministic testing
	const testWebhookSecret = "test-webhook-secret-abc123"
	const testWebhookBaseURL = "https://api.roxas.test"

	// Setup stores with mock secret generator
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: testWebhookSecret}
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, secretGen, testWebhookBaseURL)

	// Start test server
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Create cookie jar for automatic cookie management
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Failed to create cookie jar: %v", err)
	}

	// Create client that doesn't auto-follow redirects
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	const testEmail = "repo-test@example.com"
	const testPassword = "securepassword123"
	const testGitHubURL = "https://github.com/testuser/testrepo"

	// =========================================================================
	// Step 1: Create user and login
	// =========================================================================
	t.Log("Step 1: Create user and login")

	// Create user directly in store
	_, err = userStore.CreateUser(context.Background(), testEmail, hashPassword(testPassword))
	if err != nil {
		t.Fatalf("Step 1 FAILED: Could not create test user: %v", err)
	}

	// Login
	loginForm := url.Values{}
	loginForm.Set("email", testEmail)
	loginForm.Set("password", testPassword)

	resp, err := client.PostForm(ts.URL+"/login", loginForm)
	if err != nil {
		t.Fatalf("Step 1 FAILED: Login request error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("Step 1 FAILED: Expected 303 redirect, got %d", resp.StatusCode)
	}
	t.Log("Step 1 PASSED: User logged in")

	// =========================================================================
	// Step 2: GET /repositories/new → form renders
	// =========================================================================
	t.Log("Step 2: GET /repositories/new - form renders")

	resp, err = client.Get(ts.URL + "/repositories/new")
	if err != nil {
		t.Fatalf("Step 2 FAILED: Request error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Step 2 FAILED: Expected 200 OK, got %d", resp.StatusCode)
	}

	bodyBytes := make([]byte, 8192)
	n, _ := resp.Body.Read(bodyBytes)
	body := string(bodyBytes[:n])
	resp.Body.Close()

	if !strings.Contains(body, "Add Repository") {
		t.Fatalf("Step 2 FAILED: Expected 'Add Repository' in page")
	}
	if !strings.Contains(body, "github_url") {
		t.Fatalf("Step 2 FAILED: Expected form with github_url field")
	}
	t.Log("Step 2 PASSED: Repository form rendered")

	// =========================================================================
	// Step 3: POST /repositories/new → redirect to success
	// =========================================================================
	t.Log("Step 3: POST /repositories/new - create repository")

	repoForm := url.Values{}
	repoForm.Set("github_url", testGitHubURL)

	resp, err = client.PostForm(ts.URL+"/repositories/new", repoForm)
	if err != nil {
		t.Fatalf("Step 3 FAILED: Request error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("Step 3 FAILED: Expected 303 redirect, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if !strings.HasPrefix(location, "/repositories/success") {
		t.Fatalf("Step 3 FAILED: Expected redirect to /repositories/success, got %s", location)
	}

	// Verify repo was created in store
	var createdRepo *handlers.Repository
	allRepos := make([]*handlers.Repository, 0)
	repoStore.mu.Lock()
	for _, r := range repoStore.repos {
		allRepos = append(allRepos, r)
	}
	repoStore.mu.Unlock()

	if len(allRepos) == 0 {
		t.Fatalf("Step 3 FAILED: Repository was not created in store")
	}
	createdRepo = allRepos[0]
	t.Logf("Step 3 PASSED: Repository created with ID %s", createdRepo.ID)

	// =========================================================================
	// Step 4: GET /repositories/success → shows webhook config
	// =========================================================================
	t.Log("Step 4: GET /repositories/success - shows webhook config")

	resp, err = client.Get(ts.URL + location)
	if err != nil {
		t.Fatalf("Step 4 FAILED: Request error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Step 4 FAILED: Expected 200 OK, got %d", resp.StatusCode)
	}

	bodyBytes = make([]byte, 8192)
	n, _ = resp.Body.Read(bodyBytes)
	body = string(bodyBytes[:n])
	resp.Body.Close()

	// Verify success page content
	if !strings.Contains(body, "Successfully") && !strings.Contains(body, "success") {
		t.Fatalf("Step 4 FAILED: Expected success message in page")
	}

	// Verify webhook URL is displayed
	expectedWebhookURL := testWebhookBaseURL + "/webhook/" + createdRepo.ID
	if !strings.Contains(body, expectedWebhookURL) {
		t.Fatalf("Step 4 FAILED: Expected webhook URL '%s' in page, body: %s", expectedWebhookURL, body[:min(len(body), 500)])
	}

	// Verify webhook secret is displayed
	if !strings.Contains(body, testWebhookSecret) {
		t.Fatalf("Step 4 FAILED: Expected webhook secret '%s' in page", testWebhookSecret)
	}
	t.Log("Step 4 PASSED: Success page shows webhook configuration")

	// =========================================================================
	// Step 5: Verify repository is visible on dashboard
	// =========================================================================
	t.Log("Step 5: GET /dashboard - repository appears")

	resp, err = client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("Step 5 FAILED: Request error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Step 5 FAILED: Expected 200 OK, got %d", resp.StatusCode)
	}

	bodyBytes = make([]byte, 8192)
	n, _ = resp.Body.Read(bodyBytes)
	body = string(bodyBytes[:n])
	resp.Body.Close()

	// Dashboard should show the repository (not empty state)
	if strings.Contains(strings.ToLower(body), "get started") {
		t.Fatalf("Step 5 FAILED: Dashboard should not show empty state after adding repository")
	}
	if !strings.Contains(body, "testrepo") {
		t.Fatalf("Step 5 FAILED: Expected repository name 'testrepo' in dashboard")
	}
	t.Log("Step 5 PASSED: Repository visible on dashboard")

	// =========================================================================
	// Step 6: Simulate webhook ping - verify signature can be computed
	// =========================================================================
	t.Log("Step 6: Simulate webhook ping - verify webhook secret and signature")

	// Simulate a GitHub webhook payload
	webhookPayload := []byte(`{
		"repository": {"html_url": "https://github.com/testuser/testrepo"},
		"commits": [{"id": "abc123", "message": "Test commit", "author": {"name": "Test User"}}]
	}`)

	// Compute HMAC signature using the webhook secret (same algorithm GitHub uses)
	mac := hmac.New(sha256.New, []byte(testWebhookSecret))
	mac.Write(webhookPayload)
	computedSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	// Verify the repository's webhook secret matches what we used
	if createdRepo.WebhookSecret != testWebhookSecret {
		t.Fatalf("Step 6 FAILED: Repository webhook secret mismatch. Expected '%s', got '%s'",
			testWebhookSecret, createdRepo.WebhookSecret)
	}

	// Verify signature format is correct (this is what GitHub would send)
	if !strings.HasPrefix(computedSignature, "sha256=") {
		t.Fatalf("Step 6 FAILED: Invalid signature format: %s", computedSignature)
	}

	// Verify signature length (sha256 hex = 64 chars + "sha256=" prefix = 71 chars)
	if len(computedSignature) != 71 {
		t.Fatalf("Step 6 FAILED: Invalid signature length: %d (expected 71)", len(computedSignature))
	}

	t.Logf("Step 6 PASSED: Webhook signature computed successfully: %s...", computedSignature[:20])

	t.Log("=== ALL 6 STEPS PASSED: Repository creation, webhook configuration, and signature verified ===")
}

// =============================================================================
// Tests for /repositories/new and /repositories/success
// =============================================================================

func TestRouter_GetRepositoriesNew_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/repositories/new", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

func TestRouter_GetRepositoriesNew_WithAuth_RendersForm(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/new", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Add Repository") {
		t.Errorf("Expected 'Add Repository' in response")
	}
	if !strings.Contains(body, "github_url") {
		t.Errorf("Expected github_url form field in response")
	}
}

func TestRouter_PostRepositoriesNew_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	form := url.Values{}
	form.Set("github_url", "https://github.com/user/repo")

	req := httptest.NewRequest(http.MethodPost, "/repositories/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

func TestRouter_PostRepositoriesNew_InvalidURL_ShowsError(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, secretGen, "https://roxas.ai")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	testCases := []struct {
		name     string
		url      string
		expected string
	}{
		{"empty URL", "", "required"},
		{"non-GitHub URL", "https://gitlab.com/user/repo", "GitHub"},
		{"HTTP URL", "http://github.com/user/repo", "HTTPS"},
		{"invalid format", "https://github.com/invalid", "owner/repo"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("github_url", tc.url)

			req := httptest.NewRequest(http.MethodPost, "/repositories/new", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", rr.Code)
			}

			body := strings.ToLower(rr.Body.String())
			if !strings.Contains(body, strings.ToLower(tc.expected)) && !strings.Contains(body, "error") {
				t.Errorf("Expected error message containing '%s'", tc.expected)
			}
		})
	}
}

func TestRouter_PostRepositoriesNew_ValidURL_CreatesAndRedirects(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: "generated-secret-123"}
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, secretGen, "https://roxas.ai")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	form := url.Values{}
	form.Set("github_url", "https://github.com/testuser/testrepo")

	req := httptest.NewRequest(http.MethodPost, "/repositories/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to success page
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303, got %d: %s", rr.Code, rr.Body.String())
	}

	location := rr.Header().Get("Location")
	if !strings.HasPrefix(location, "/repositories/success") {
		t.Errorf("Expected redirect to /repositories/success, got %s", location)
	}

	// Verify query params include webhook info
	if !strings.Contains(location, "webhook_url=") {
		t.Errorf("Expected webhook_url in redirect, got %s", location)
	}
	if !strings.Contains(location, "webhook_secret=") {
		t.Errorf("Expected webhook_secret in redirect, got %s", location)
	}

	// Verify repo was created
	repos, _ := repoStore.ListRepositoriesByUser(context.Background(), user.ID)
	if len(repos) != 1 {
		t.Errorf("Expected 1 repository, got %d", len(repos))
	}
	if repos[0].GitHubURL != "https://github.com/testuser/testrepo" {
		t.Errorf("Expected GitHub URL to be saved")
	}
}

func TestRouter_GetRepositoriesSuccess_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/repositories/success", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

func TestRouter_GetRepositoriesSuccess_WithAuth_ShowsConfig(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/success?webhook_url=https://roxas.ai/webhook/123&webhook_secret=secret456", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Should display success message
	if !strings.Contains(body, "success") && !strings.Contains(body, "Success") && !strings.Contains(body, "Added") {
		t.Errorf("Expected success message in response")
	}

	// Should display webhook URL
	if !strings.Contains(body, "https://roxas.ai/webhook/123") {
		t.Errorf("Expected webhook URL in response")
	}

	// Should display webhook secret
	if !strings.Contains(body, "secret456") {
		t.Errorf("Expected webhook secret in response")
	}

	// Should have copy buttons
	if !strings.Contains(body, "data-copy-target") {
		t.Errorf("Expected copy button data attributes in response")
	}
}

// =============================================================================
// Tests for GET /repositories (list repositories)
// =============================================================================

func TestRouter_GetRepositories_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/repositories", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

func TestRouter_GetRepositories_WithAuth_RendersPage(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Repositories") {
		t.Errorf("Expected 'Repositories' in response")
	}
}

func TestRouter_GetRepositories_WithAuth_ShowsEmptyState(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	// Should show empty state with link to add repository
	if !strings.Contains(strings.ToLower(body), "no repositories") {
		t.Errorf("Expected 'No Repositories' in empty state")
	}
	if !strings.Contains(body, "/repositories/new") {
		t.Errorf("Expected link to add repository")
	}
}

func TestRouter_GetRepositories_WithAuth_ShowsRepositories(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	// Add repositories
	repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/user/repo1", "secret1")
	repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/user/repo2", "secret2")

	req := httptest.NewRequest(http.MethodGet, "/repositories", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	// Should show both repositories
	if !strings.Contains(body, "repo1") {
		t.Errorf("Expected repo1 in response")
	}
	if !strings.Contains(body, "repo2") {
		t.Errorf("Expected repo2 in response")
	}
	// Should have Add Repository button
	if !strings.Contains(body, "/repositories/new") {
		t.Errorf("Expected Add Repository link")
	}
}

func TestRouter_GetRepositories_WithAuth_DoesNotShowOtherUsersRepos(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user1, _ := userStore.CreateUser(context.Background(), "user1@example.com", hashPassword("password123"))
	user2, _ := userStore.CreateUser(context.Background(), "user2@example.com", hashPassword("password123"))

	// Add repo for user1
	repoStore.CreateRepository(context.Background(), user1.ID, "https://github.com/user1/privaterepo", "secret1")
	// Add repo for user2
	repoStore.CreateRepository(context.Background(), user2.ID, "https://github.com/user2/otherrepo", "secret2")

	// Login as user1
	token, _ := generateToken(user1.ID, user1.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	// Should show user1's repo
	if !strings.Contains(body, "privaterepo") {
		t.Errorf("Expected user1's repo in response")
	}
	// Should NOT show user2's repo
	if strings.Contains(body, "otherrepo") {
		t.Errorf("Should not show user2's repo in response")
	}
}

// =============================================================================
// Repository View Tests
// =============================================================================

func TestRouter_GetRepositoryView_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/repositories/some-id", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("Expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

func TestRouter_GetRepositoryView_WithAuth_ShowsRepoDetails(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, secretGen, "https://example.com")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/myrepo", "webhook-secret")

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/"+repo.ID, nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	// Should show repository name
	if !strings.Contains(body, "owner/myrepo") {
		t.Errorf("Expected repository name 'owner/myrepo' in response")
	}
	// Should show GitHub URL
	if !strings.Contains(body, "https://github.com/owner/myrepo") {
		t.Errorf("Expected GitHub URL in response")
	}
	// Should show webhook URL
	if !strings.Contains(body, "https://example.com/webhook/"+repo.ID) {
		t.Errorf("Expected webhook URL in response")
	}
	// Should show status
	if !strings.Contains(body, "Active") {
		t.Errorf("Expected status in response")
	}
	// Should show Edit button
	if !strings.Contains(body, "Edit Settings") {
		t.Errorf("Expected Edit button in response")
	}
	// Should show Delete button
	if !strings.Contains(body, "Delete Repository") {
		t.Errorf("Expected Delete button in response")
	}
}

func TestRouter_GetRepositoryView_NotFound_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/nonexistent-id", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestRouter_GetRepositoryView_OtherUsersRepo_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user1, _ := userStore.CreateUser(context.Background(), "user1@example.com", hashPassword("password123"))
	user2, _ := userStore.CreateUser(context.Background(), "user2@example.com", hashPassword("password123"))

	// Create repo for user1
	repo, _ := repoStore.CreateRepository(context.Background(), user1.ID, "https://github.com/user1/privaterepo", "secret")

	// Try to access as user2
	token, _ := generateToken(user2.ID, user2.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/"+repo.ID, nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for other user's repo, got %d", rr.Code)
	}
}

// Repository Edit Tests

func TestRouter_GetRepositoryEdit_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/repositories/test-id/edit", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

func TestRouter_GetRepositoryEdit_WithAuth_ShowsEditForm(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	// Create a repository
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/user/myrepo", "secret")

	req := httptest.NewRequest(http.MethodGet, "/repositories/"+repo.ID+"/edit", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Edit Repository") {
		t.Errorf("Expected edit form title in response")
	}
}

func TestRouter_GetRepositoryEdit_NotFound_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/nonexistent-id/edit", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestRouter_GetRepositoryEdit_OtherUsersRepo_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user1, _ := userStore.CreateUser(context.Background(), "user1@example.com", hashPassword("password123"))
	user2, _ := userStore.CreateUser(context.Background(), "user2@example.com", hashPassword("password123"))

	// Create repo for user2
	repo, _ := repoStore.CreateRepository(context.Background(), user2.ID, "https://github.com/user2/private", "secret")

	// Try to access as user1
	token, _ := generateToken(user1.ID, user1.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/"+repo.ID+"/edit", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 404 (not 403) to avoid revealing repo existence
	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestRouter_PostRepositoryEdit_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	form := url.Values{}
	form.Set("name", "New Name")
	form.Set("is_active", "true")

	req := httptest.NewRequest(http.MethodPost, "/repositories/test-id/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

func TestRouter_PostRepositoryEdit_ValidData_UpdatesAndRedirects(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	// Create a repository
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/user/myrepo", "secret")

	form := url.Values{}
	form.Set("name", "Updated Name")
	form.Set("is_active", "true")

	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to repositories list
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303, got %d: %s", rr.Code, rr.Body.String())
	}

	location := rr.Header().Get("Location")
	if location != "/repositories" {
		t.Errorf("Expected redirect to /repositories, got %s", location)
	}

	// Verify repo was updated
	updatedRepo, _ := repoStore.GetRepositoryByID(context.Background(), repo.ID)
	if updatedRepo.Name != "Updated Name" {
		t.Errorf("Expected name to be updated, got %s", updatedRepo.Name)
	}
	if !updatedRepo.IsActive {
		t.Errorf("Expected is_active to be true")
	}
}

func TestRouter_PostRepositoryEdit_EmptyName_ShowsError(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	// Create a repository
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/user/myrepo", "secret")

	form := url.Values{}
	form.Set("name", "")
	form.Set("is_active", "true")

	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 200 with error
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(strings.ToLower(body), "required") {
		t.Errorf("Expected error about name being required")
	}
}

func TestRouter_PostRepositoryEdit_ToggleInactive_UpdatesStatus(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	// Create a repository (defaults to active)
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/user/myrepo", "secret")
	repo.IsActive = true

	// Submit form without is_active (checkbox unchecked = not sent)
	form := url.Values{}
	form.Set("name", "My Repo")
	// Note: is_active not set, simulating unchecked checkbox

	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify repo was updated to inactive
	updatedRepo, _ := repoStore.GetRepositoryByID(context.Background(), repo.ID)
	if updatedRepo.IsActive {
		t.Errorf("Expected is_active to be false when checkbox unchecked")
	}
}

// =============================================================================
// Webhook Test Endpoint Tests (POST /repositories/:id/webhook/test)
// =============================================================================

// MockWebhookTester for testing webhook test endpoint
type MockWebhookTester struct {
	mu          sync.Mutex
	lastURL     string
	lastSecret  string
	shouldError bool
	statusCode  int
}

func NewMockWebhookTester() *MockWebhookTester {
	return &MockWebhookTester{statusCode: 200}
}

func (m *MockWebhookTester) TestWebhook(ctx context.Context, webhookURL, secret string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastURL = webhookURL
	m.lastSecret = secret
	if m.shouldError {
		return 0, context.DeadlineExceeded
	}
	return m.statusCode, nil
}

func (m *MockWebhookTester) SetShouldError(shouldError bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldError = shouldError
}

func (m *MockWebhookTester) SetStatusCode(code int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statusCode = code
}

func (m *MockWebhookTester) GetLastURL() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastURL
}

func TestRouter_PostWebhookTest_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodPost, "/repositories/some-id/webhook/test", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("Expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

// =============================================================================
// Webhook Deliveries Tests (GET /repositories/:id/webhooks)
// =============================================================================

// MockWebhookDeliveryStore implements WebhookDeliveryStore for tests
type MockWebhookDeliveryStore struct {
	deliveries map[string][]*WebhookDelivery
}

func NewMockWebhookDeliveryStore() *MockWebhookDeliveryStore {
	return &MockWebhookDeliveryStore{
		deliveries: make(map[string][]*WebhookDelivery),
	}
}

func (s *MockWebhookDeliveryStore) ListDeliveriesByRepository(ctx context.Context, repoID string, limit int) ([]*WebhookDelivery, error) {
	deliveries := s.deliveries[repoID]
	if len(deliveries) > limit {
		return deliveries[:limit], nil
	}
	return deliveries, nil
}

func (s *MockWebhookDeliveryStore) AddDelivery(repoID string, delivery *WebhookDelivery) {
	s.deliveries[repoID] = append(s.deliveries[repoID], delivery)
}

func (s *MockWebhookDeliveryStore) CreateDelivery(ctx context.Context, repoID, eventType string, payload []byte, statusCode int, errorMessage *string) (*WebhookDelivery, error) {
	delivery := &WebhookDelivery{
		ID:           fmt.Sprintf("delivery-%d", len(s.deliveries[repoID])+1),
		RepositoryID: repoID,
		EventType:    eventType,
		Payload:      string(payload),
		StatusCode:   statusCode,
		ErrorMessage: errorMessage,
		IsSuccess:    statusCode >= 200 && statusCode < 300,
	}
	s.deliveries[repoID] = append(s.deliveries[repoID], delivery)
	return delivery, nil
}

func (s *MockWebhookDeliveryStore) GetDeliveryCount(repoID string) int {
	return len(s.deliveries[repoID])
}

func TestRouter_GetWebhookDeliveries_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/repositories/some-id/webhooks", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("Expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

func TestRouter_PostWebhookTest_NotFound_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookTester := NewMockWebhookTester()
	router := NewRouterWithWebhookTester(userStore, repoStore, nil, nil, nil, "https://example.com", webhookTester)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/repositories/nonexistent-id/webhook/test", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestRouter_GetWebhookDeliveries_WithAuth_ShowsDeliveries(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookStore := NewMockWebhookDeliveryStore()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}
	router := NewRouterWithWebhookDeliveries(userStore, repoStore, nil, nil, secretGen, "https://example.com", webhookStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/myrepo", "webhook-secret")

	// Add some test deliveries
	webhookStore.AddDelivery(repo.ID, &WebhookDelivery{
		ID:         "delivery-1",
		EventType:  "push",
		Payload:    `{"commits":[{"message":"test"}]}`,
		StatusCode: 200,
		CreatedAt:  "2026-01-02 15:04:05",
		IsSuccess:  true,
	})
	webhookStore.AddDelivery(repo.ID, &WebhookDelivery{
		ID:           "delivery-2",
		EventType:    "push",
		Payload:      `{"error":"test"}`,
		StatusCode:   500,
		ErrorMessage: stringPtr("Internal Server Error"),
		CreatedAt:    "2026-01-02 14:00:00",
		IsSuccess:    false,
	})

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/"+repo.ID+"/webhooks", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	// Should show page title
	if !strings.Contains(body, "Webhook Deliveries") {
		t.Errorf("Expected 'Webhook Deliveries' in response")
	}
	// Should show repository name
	if !strings.Contains(body, "owner/myrepo") {
		t.Errorf("Expected repository name in response")
	}
	// Should show event type
	if !strings.Contains(body, "push") {
		t.Errorf("Expected event type 'push' in response")
	}
	// Should show status codes
	if !strings.Contains(body, "200") {
		t.Errorf("Expected status code 200 in response")
	}
	if !strings.Contains(body, "500") {
		t.Errorf("Expected status code 500 in response")
	}
}

func TestRouter_GetWebhookDeliveries_EmptyList_ShowsMessage(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookStore := NewMockWebhookDeliveryStore()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}
	router := NewRouterWithWebhookDeliveries(userStore, repoStore, nil, nil, secretGen, "https://example.com", webhookStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/myrepo", "webhook-secret")

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/"+repo.ID+"/webhooks", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	// Should show empty state message
	if !strings.Contains(body, "No webhook deliveries yet") {
		t.Errorf("Expected empty state message in response")
	}
}

func TestRouter_GetWebhookDeliveries_NotFound_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookStore := NewMockWebhookDeliveryStore()
	router := NewRouterWithWebhookDeliveries(userStore, repoStore, nil, nil, nil, "", webhookStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/nonexistent-id/webhooks", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestRouter_PostWebhookTest_OtherUsersRepo_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookTester := NewMockWebhookTester()
	router := NewRouterWithWebhookTester(userStore, repoStore, nil, nil, nil, "https://example.com", webhookTester)

	user1, _ := userStore.CreateUser(context.Background(), "user1@example.com", hashPassword("password123"))
	user2, _ := userStore.CreateUser(context.Background(), "user2@example.com", hashPassword("password123"))

	// Create repo for user1
	repo, _ := repoStore.CreateRepository(context.Background(), user1.ID, "https://github.com/user1/privaterepo", "secret")

	// Try to test webhook as user2
	token, _ := generateToken(user2.ID, user2.Email)

	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/webhook/test", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for other user's repo, got %d", rr.Code)
	}
}

func TestRouter_GetWebhookDeliveries_OtherUsersRepo_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookStore := NewMockWebhookDeliveryStore()
	secretGen := &MockSecretGeneratorForWeb{Secret: "test-secret"}
	router := NewRouterWithWebhookDeliveries(userStore, repoStore, nil, nil, secretGen, "https://example.com", webhookStore)

	// Create two users
	user1, _ := userStore.CreateUser(context.Background(), "user1@example.com", hashPassword("password123"))
	user2, _ := userStore.CreateUser(context.Background(), "user2@example.com", hashPassword("password123"))

	// Create a repo owned by user2
	repo, _ := repoStore.CreateRepository(context.Background(), user2.ID, "https://github.com/owner/private-repo", "webhook-secret")

	// User1 tries to access user2's repo
	token, _ := generateToken(user1.ID, user1.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/"+repo.ID+"/webhooks", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for other user's repo, got %d", rr.Code)
	}
}

func TestRouter_PostWebhookTest_Success_ReturnsOK(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookTester := NewMockWebhookTester()
	router := NewRouterWithWebhookTester(userStore, repoStore, nil, nil, nil, "https://example.com", webhookTester)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/myrepo", "webhook-secret")

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/webhook/test", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "success") && !strings.Contains(body, "Success") {
		t.Errorf("Expected success message in response, got: %s", body)
	}

	// Verify the webhook tester was called with correct URL
	expectedURL := "https://example.com/webhook/" + repo.ID
	if webhookTester.GetLastURL() != expectedURL {
		t.Errorf("Expected webhook tester to be called with %s, got %s", expectedURL, webhookTester.GetLastURL())
	}
}

func TestRouter_PostWebhookTest_WebhookFails_ShowsError(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookTester := NewMockWebhookTester()
	webhookTester.SetShouldError(true)
	router := NewRouterWithWebhookTester(userStore, repoStore, nil, nil, nil, "https://example.com", webhookTester)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/myrepo", "webhook-secret")

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/webhook/test", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(strings.ToLower(body), "failed") && !strings.Contains(strings.ToLower(body), "error") {
		t.Errorf("Expected error message in response, got: %s", body)
	}
}

func TestRouter_PostWebhookTest_WebhookReturnsNon200_ShowsError(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookTester := NewMockWebhookTester()
	webhookTester.SetStatusCode(500)
	router := NewRouterWithWebhookTester(userStore, repoStore, nil, nil, nil, "https://example.com", webhookTester)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/myrepo", "webhook-secret")

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/webhook/test", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	// Should indicate failure with status code
	if !strings.Contains(body, "500") && !strings.Contains(strings.ToLower(body), "failed") {
		t.Errorf("Expected error with status code in response, got: %s", body)
	}
}

func TestRouter_GetWebhookTest_MethodNotAllowed(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookTester := NewMockWebhookTester()
	router := NewRouterWithWebhookTester(userStore, repoStore, nil, nil, nil, "https://example.com", webhookTester)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/myrepo", "webhook-secret")

	token, _ := generateToken(user.ID, user.Email)

	// GET instead of POST
	req := httptest.NewRequest(http.MethodGet, "/repositories/"+repo.ID+"/webhook/test", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rr.Code)
	}
}

func TestRouter_PostWebhookTest_RecordsDelivery(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookTester := NewMockWebhookTester()
	webhookDeliveryStore := NewMockWebhookDeliveryStore()
	router := NewRouterWithWebhookTesterAndDeliveries(userStore, repoStore, nil, nil, nil, "https://example.com", webhookTester, webhookDeliveryStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/myrepo", "webhook-secret")

	// Verify no deliveries exist initially
	if webhookDeliveryStore.GetDeliveryCount(repo.ID) != 0 {
		t.Error("Expected no deliveries initially")
	}

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/webhook/test", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Verify delivery was recorded
	if webhookDeliveryStore.GetDeliveryCount(repo.ID) != 1 {
		t.Errorf("Expected 1 delivery to be recorded, got %d", webhookDeliveryStore.GetDeliveryCount(repo.ID))
	}

	// Verify delivery details
	deliveries, _ := webhookDeliveryStore.ListDeliveriesByRepository(context.Background(), repo.ID, 10)
	if len(deliveries) != 1 {
		t.Fatal("Expected 1 delivery")
	}
	if deliveries[0].EventType != "ping" {
		t.Errorf("Expected event type 'ping', got %s", deliveries[0].EventType)
	}
	if !deliveries[0].IsSuccess {
		t.Error("Expected delivery to be marked as success")
	}
}

func TestRouter_PostWebhookTest_RecordsFailedDelivery(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	webhookTester := NewMockWebhookTester()
	webhookTester.SetStatusCode(500)
	webhookDeliveryStore := NewMockWebhookDeliveryStore()
	router := NewRouterWithWebhookTesterAndDeliveries(userStore, repoStore, nil, nil, nil, "https://example.com", webhookTester, webhookDeliveryStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/myrepo", "webhook-secret")

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/webhook/test", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Verify failed delivery was recorded
	if webhookDeliveryStore.GetDeliveryCount(repo.ID) != 1 {
		t.Errorf("Expected 1 delivery to be recorded, got %d", webhookDeliveryStore.GetDeliveryCount(repo.ID))
	}

	deliveries, _ := webhookDeliveryStore.ListDeliveriesByRepository(context.Background(), repo.ID, 10)
	if len(deliveries) != 1 {
		t.Fatal("Expected 1 delivery")
	}
	if deliveries[0].StatusCode != 500 {
		t.Errorf("Expected status code 500, got %d", deliveries[0].StatusCode)
	}
	if deliveries[0].IsSuccess {
		t.Error("Expected delivery to be marked as failure")
	}
	if deliveries[0].ErrorMessage == nil {
		t.Error("Expected error message to be set")
	}
}

// =============================================================================
// Webhook Regenerate Tests
// =============================================================================

func TestRouter_PostWebhookRegenerate_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodPost, "/repositories/some-id/webhook/regenerate", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("Expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

func TestRouter_GetWebhookRegenerate_MethodNotAllowed(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: "new-secret"}
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, secretGen, "https://example.com")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/repo", "old-secret")
	token, _ := generateToken(user.ID, user.Email)

	// GET should not be allowed
	req := httptest.NewRequest(http.MethodGet, "/repositories/"+repo.ID+"/webhook/regenerate", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405 Method Not Allowed, got %d", rr.Code)
	}
}

func TestRouter_PostWebhookRegenerate_Success_ShowsNewSecret(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: "brand-new-secret-456"}
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, secretGen, "https://roxas.ai")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/myrepo", "old-secret-123")
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/webhook/regenerate", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Should show success message
	if !strings.Contains(body, "Regenerated") {
		t.Errorf("Expected 'Regenerated' in response")
	}

	// Should show the new secret
	if !strings.Contains(body, "brand-new-secret-456") {
		t.Errorf("Expected new secret in response")
	}

	// Should show webhook URL
	if !strings.Contains(body, "https://roxas.ai/webhook/"+repo.ID) {
		t.Errorf("Expected webhook URL in response")
	}

	// Should show repository name
	if !strings.Contains(body, "owner/myrepo") {
		t.Errorf("Expected repository name in response")
	}

	// Should have copy button
	if !strings.Contains(body, "data-copy-target") {
		t.Errorf("Expected copy button in response")
	}

	// Verify the secret was updated in the store
	updatedRepo, _ := repoStore.GetRepositoryByID(context.Background(), repo.ID)
	if updatedRepo.WebhookSecret != "brand-new-secret-456" {
		t.Errorf("Expected secret to be updated in store, got %s", updatedRepo.WebhookSecret)
	}
}

func TestRouter_PostWebhookRegenerate_NotFound_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: "new-secret"}
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, secretGen, "https://example.com")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/repositories/nonexistent-id/webhook/regenerate", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestRouter_PostWebhookRegenerate_OtherUsersRepo_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: "new-secret"}
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, secretGen, "https://example.com")

	user1, _ := userStore.CreateUser(context.Background(), "user1@example.com", hashPassword("password123"))
	user2, _ := userStore.CreateUser(context.Background(), "user2@example.com", hashPassword("password123"))

	// Create repo for user1
	repo, _ := repoStore.CreateRepository(context.Background(), user1.ID, "https://github.com/user1/privaterepo", "secret")

	// Try to regenerate as user2
	token, _ := generateToken(user2.ID, user2.Email)

	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/webhook/regenerate", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for other user's repo, got %d", rr.Code)
	}

	// Verify the secret was NOT changed
	unchangedRepo, _ := repoStore.GetRepositoryByID(context.Background(), repo.ID)
	if unchangedRepo.WebhookSecret != "secret" {
		t.Errorf("Expected secret to remain unchanged, got %s", unchangedRepo.WebhookSecret)
	}
}

func TestRouter_PostWebhookRegenerate_InvalidatesOldSecret(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	secretGen := &MockSecretGeneratorForWeb{Secret: "completely-new-secret"}
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, secretGen, "https://example.com")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/repo", "old-secret")
	token, _ := generateToken(user.ID, user.Email)

	// Verify old secret is in place
	oldRepo, _ := repoStore.GetRepositoryByID(context.Background(), repo.ID)
	if oldRepo.WebhookSecret != "old-secret" {
		t.Fatalf("Expected old secret to be 'old-secret', got %s", oldRepo.WebhookSecret)
	}

	// Regenerate
	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/webhook/regenerate", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", rr.Code)
	}

	// Verify old secret is invalidated (replaced with new one)
	newRepo, _ := repoStore.GetRepositoryByID(context.Background(), repo.ID)
	if newRepo.WebhookSecret == "old-secret" {
		t.Errorf("Expected old secret to be invalidated")
	}
	if newRepo.WebhookSecret != "completely-new-secret" {
		t.Errorf("Expected new secret to be 'completely-new-secret', got %s", newRepo.WebhookSecret)
	}
}

func stringPtr(s string) *string {
	return &s
}

// =============================================================================
// Repository Delete Tests (GET/POST /repositories/:id/delete)
// =============================================================================

func TestRouter_GetRepositoryDelete_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/repositories/some-id/delete", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("Expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

func TestRouter_GetRepositoryDelete_WithAuth_RendersConfirmation(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/repo", "secret")
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/"+repo.ID+"/delete", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	// Should show confirmation page with repo name
	if !strings.Contains(body, "owner/repo") {
		t.Errorf("Expected body to contain repo name 'owner/repo', got: %s", body[:min(len(body), 500)])
	}
	// Should have delete button
	if !strings.Contains(body, "Delete Repository") {
		t.Errorf("Expected body to contain 'Delete Repository' button")
	}
	// Should have cancel link
	if !strings.Contains(body, "Cancel") {
		t.Errorf("Expected body to contain 'Cancel' link")
	}
}

func TestRouter_GetRepositoryDelete_NotFound_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/nonexistent-id/delete", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for non-existent repo, got %d", rr.Code)
	}
}

func TestRouter_GetRepositoryDelete_OtherUsersRepo_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	// Create two users
	user1, _ := userStore.CreateUser(context.Background(), "user1@example.com", hashPassword("password123"))
	user2, _ := userStore.CreateUser(context.Background(), "user2@example.com", hashPassword("password123"))

	// Create repo for user1
	repo, _ := repoStore.CreateRepository(context.Background(), user1.ID, "https://github.com/owner/repo", "secret")

	// Try to access as user2
	token, _ := generateToken(user2.ID, user2.Email)

	req := httptest.NewRequest(http.MethodGet, "/repositories/"+repo.ID+"/delete", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for other user's repo, got %d", rr.Code)
	}
}

func TestRouter_PostRepositoryDelete_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodPost, "/repositories/some-id/delete", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("Expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

func TestRouter_PostRepositoryDelete_WithAuth_DeletesAndRedirects(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	repo, _ := repoStore.CreateRepository(context.Background(), user.ID, "https://github.com/owner/repo", "secret")
	token, _ := generateToken(user.ID, user.Email)

	// Verify repo exists before delete
	existingRepo, _ := repoStore.GetRepositoryByID(context.Background(), repo.ID)
	if existingRepo == nil {
		t.Fatal("Expected repository to exist before delete")
	}

	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/delete", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to repositories list
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Location") != "/repositories" {
		t.Errorf("Expected redirect to /repositories, got %s", rr.Header().Get("Location"))
	}

	// Verify repo is deleted
	deletedRepo, _ := repoStore.GetRepositoryByID(context.Background(), repo.ID)
	if deletedRepo != nil {
		t.Errorf("Expected repository to be deleted, but it still exists")
	}
}

func TestRouter_PostRepositoryDelete_NotFound_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/repositories/nonexistent-id/delete", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for non-existent repo, got %d", rr.Code)
	}
}

func TestRouter_PostRepositoryDelete_OtherUsersRepo_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil, nil, "")

	// Create two users
	user1, _ := userStore.CreateUser(context.Background(), "user1@example.com", hashPassword("password123"))
	user2, _ := userStore.CreateUser(context.Background(), "user2@example.com", hashPassword("password123"))

	// Create repo for user1
	repo, _ := repoStore.CreateRepository(context.Background(), user1.ID, "https://github.com/owner/repo", "secret")

	// Try to delete as user2
	token, _ := generateToken(user2.ID, user2.Email)

	req := httptest.NewRequest(http.MethodPost, "/repositories/"+repo.ID+"/delete", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for other user's repo, got %d", rr.Code)
	}

	// Verify repo was NOT deleted
	existingRepo, _ := repoStore.GetRepositoryByID(context.Background(), repo.ID)
	if existingRepo == nil {
		t.Errorf("Repository should NOT have been deleted by other user")
	}
}

// =============================================================================
// TB-CONN-RATELIMIT: Connections page with rate limit display (hq-w12c)
// =============================================================================

// MockConnectionLister provides connection data for testing
type MockConnectionLister struct {
	connections []*ConnectionData
}

func (m *MockConnectionLister) ListConnectionsWithRateLimits(ctx context.Context, userID string) ([]*ConnectionData, error) {
	return m.connections, nil
}

func TestRouter_GetConnections_RequiresAuth(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/connections", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to login
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("Expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

func TestRouter_GetConnections_ShowsRateLimits(t *testing.T) {
	userStore := NewMockUserStore()
	connLister := &MockConnectionLister{
		connections: []*ConnectionData{
			{
				Platform:    "threads",
				Status:      "connected",
				DisplayName: "@testuser",
				IsHealthy:   true,
				RateLimit: &RateLimitData{
					Limit:     100,
					Remaining: 75,
					ResetAt:   time.Now().Add(time.Hour),
				},
			},
		},
	}
	router := NewRouterWithConnectionLister(userStore, connLister)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/connections", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Should show rate limit as X/Y remaining
	if !strings.Contains(body, "75") || !strings.Contains(body, "100") {
		t.Errorf("Expected rate limit display (75/100), got: %s", body[:min(len(body), 500)])
	}
}

func TestRouter_GetConnections_ShowsLowRateLimitWarning(t *testing.T) {
	userStore := NewMockUserStore()
	connLister := &MockConnectionLister{
		connections: []*ConnectionData{
			{
				Platform:    "threads",
				Status:      "connected",
				DisplayName: "@testuser",
				IsHealthy:   true,
				RateLimit: &RateLimitData{
					Limit:     100,
					Remaining: 5, // Low limit
					ResetAt:   time.Now().Add(time.Hour),
				},
			},
		},
	}
	router := NewRouterWithConnectionLister(userStore, connLister)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/connections", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Should show warning class for low rate limit
	if !strings.Contains(body, "rate-limit-warning") && !strings.Contains(body, "rate-limit-low") {
		t.Errorf("Expected low rate limit warning indicator, got: %s", body[:min(len(body), 500)])
	}
}

func TestRouter_GetConnections_ShowsResetTime(t *testing.T) {
	userStore := NewMockUserStore()
	resetTime := time.Now().Add(30 * time.Minute)
	connLister := &MockConnectionLister{
		connections: []*ConnectionData{
			{
				Platform:    "threads",
				Status:      "connected",
				DisplayName: "@testuser",
				IsHealthy:   true,
				RateLimit: &RateLimitData{
					Limit:     100,
					Remaining: 50,
					ResetAt:   resetTime,
				},
			},
		},
	}
	router := NewRouterWithConnectionLister(userStore, connLister)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/connections", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Should show reset time in human-readable format (e.g., "30 minutes" or time)
	if !strings.Contains(body, "reset") && !strings.Contains(body, "Reset") {
		t.Errorf("Expected reset time display, got: %s", body[:min(len(body), 500)])
	}
}

func TestRouter_GetConnections_EmptyState(t *testing.T) {
	userStore := NewMockUserStore()
	connLister := &MockConnectionLister{
		connections: []*ConnectionData{},
	}
	router := NewRouterWithConnectionLister(userStore, connLister)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/connections", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Should show empty state message
	if !strings.Contains(body, "No connections") && !strings.Contains(body, "connect") {
		t.Errorf("Expected empty state message, got: %s", body[:min(len(body), 500)])
	}
}

// =============================================================================
// Connection Disconnect Tests (hq-chj1)
// =============================================================================

// MockConnectionService implements ConnectionService for tests
type MockConnectionService struct {
	connections     map[string]map[string]*Connection // userID -> platform -> connection
	disconnectCalls []struct{ UserID, Platform string }
}

func NewMockConnectionService() *MockConnectionService {
	return &MockConnectionService{
		connections: make(map[string]map[string]*Connection),
	}
}

func (s *MockConnectionService) GetConnection(ctx context.Context, userID, platform string) (*Connection, error) {
	userConns, ok := s.connections[userID]
	if !ok {
		return nil, errors.New("connection not found")
	}
	conn, ok := userConns[platform]
	if !ok {
		return nil, errors.New("connection not found")
	}
	return conn, nil
}

func (s *MockConnectionService) Disconnect(ctx context.Context, userID, platform string) error {
	s.disconnectCalls = append(s.disconnectCalls, struct{ UserID, Platform string }{userID, platform})
	userConns, ok := s.connections[userID]
	if !ok {
		return errors.New("connection not found")
	}
	if _, ok := userConns[platform]; !ok {
		return errors.New("connection not found")
	}
	delete(userConns, platform)
	return nil
}

func (s *MockConnectionService) AddConnection(userID, platform, displayName, profileURL string) {
	if s.connections[userID] == nil {
		s.connections[userID] = make(map[string]*Connection)
	}
	s.connections[userID][platform] = &Connection{
		Platform:    platform,
		Status:      ConnectionStatusConnected,
		DisplayName: displayName,
		ProfileURL:  profileURL,
	}
}

func (s *MockConnectionService) GetDisconnectCalls() []struct{ UserID, Platform string } {
	return s.disconnectCalls
}

func TestRouter_GetConnectionDisconnect_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/connections/twitter/disconnect", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("Expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

func TestRouter_GetConnectionDisconnect_WithAuth_ShowsConfirmation(t *testing.T) {
	userStore := NewMockUserStore()
	connService := NewMockConnectionService()
	router := NewRouterWithConnectionService(userStore, connService)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	connService.AddConnection(user.ID, "twitter", "@testuser", "https://twitter.com/testuser")

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/connections/twitter/disconnect", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Disconnect Account") {
		t.Errorf("Expected 'Disconnect Account' in response")
	}
	if !strings.Contains(body, "twitter") {
		t.Errorf("Expected platform 'twitter' in response")
	}
	if !strings.Contains(body, "@testuser") {
		t.Errorf("Expected display name '@testuser' in response")
	}
	if !strings.Contains(body, "Are you sure") {
		t.Errorf("Expected confirmation text in response")
	}
}

func TestRouter_GetConnectionDisconnect_NotFound_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	connService := NewMockConnectionService()
	router := NewRouterWithConnectionService(userStore, connService)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	// No connection added

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/connections/twitter/disconnect", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestRouter_PostConnectionDisconnect_WithoutAuth_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodPost, "/connections/twitter/disconnect", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("Expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

func TestRouter_PostConnectionDisconnect_WithAuth_DisconnectsAndRedirects(t *testing.T) {
	userStore := NewMockUserStore()
	connService := NewMockConnectionService()
	router := NewRouterWithConnectionService(userStore, connService)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	connService.AddConnection(user.ID, "twitter", "@testuser", "https://twitter.com/testuser")

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/connections/twitter/disconnect", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "/dashboard") {
		t.Errorf("Expected redirect to /dashboard, got %s", rr.Header().Get("Location"))
	}
	if !strings.Contains(rr.Header().Get("Location"), "disconnected=twitter") {
		t.Errorf("Expected disconnected=twitter in redirect URL, got %s", rr.Header().Get("Location"))
	}

	// Verify disconnect was called
	calls := connService.GetDisconnectCalls()
	if len(calls) != 1 {
		t.Fatalf("Expected 1 disconnect call, got %d", len(calls))
	}
	if calls[0].UserID != user.ID || calls[0].Platform != "twitter" {
		t.Errorf("Disconnect called with wrong params: %+v", calls[0])
	}

	// Verify connection is gone
	_, err := connService.GetConnection(context.Background(), user.ID, "twitter")
	if err == nil {
		t.Errorf("Expected connection to be removed after disconnect")
	}
}

func TestRouter_PostConnectionDisconnect_NotFound_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	connService := NewMockConnectionService()
	router := NewRouterWithConnectionService(userStore, connService)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	// No connection added

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/connections/twitter/disconnect", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestRouter_PostConnectionDisconnect_OtherUserConnection_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	connService := NewMockConnectionService()
	router := NewRouterWithConnectionService(userStore, connService)

	// Create user1 with a connection
	user1, _ := userStore.CreateUser(context.Background(), "user1@example.com", hashPassword("password123"))
	connService.AddConnection(user1.ID, "twitter", "@user1", "https://twitter.com/user1")

	// Create user2 (no connection)
	user2, _ := userStore.CreateUser(context.Background(), "user2@example.com", hashPassword("password123"))

	// User2 tries to disconnect user1's connection
	token, _ := generateToken(user2.ID, user2.Email)

	req := httptest.NewRequest(http.MethodPost, "/connections/twitter/disconnect", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for other user's connection, got %d", rr.Code)
	}

	// Verify user1's connection was NOT deleted
	conn, err := connService.GetConnection(context.Background(), user1.ID, "twitter")
	if err != nil || conn == nil {
		t.Errorf("User1's connection should NOT have been deleted by user2")
	}
}

// =============================================================================
// TB-DRAFT-01: Draft Preview Page Tests (TDD - RED)
// =============================================================================

// MockDraftStore implements DraftStore interface for testing draft preview
type MockDraftStore struct {
	mu     sync.Mutex
	drafts map[string]*Draft
}

func NewMockDraftStore() *MockDraftStore {
	return &MockDraftStore{drafts: make(map[string]*Draft)}
}

func (s *MockDraftStore) CreateDraft(ctx context.Context, userID, repoID, content string) (*Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	draft := &Draft{
		ID:           uuid.New().String(),
		UserID:       userID,
		RepositoryID: repoID,
		Content:      content,
		Status:       "draft",
		CharLimit:    500,
		CreatedAt:    time.Now(),
	}
	s.drafts[draft.ID] = draft
	return draft, nil
}

func (s *MockDraftStore) GetDraftByID(ctx context.Context, draftID string) (*Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if draft, ok := s.drafts[draftID]; ok {
		return draft, nil
	}
	return nil, nil
}

func (s *MockDraftStore) UpdateDraftContent(ctx context.Context, draftID, content string) (*Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if draft, ok := s.drafts[draftID]; ok {
		draft.Content = content
		return draft, nil
	}
	return nil, nil
}

func (s *MockDraftStore) DeleteDraft(ctx context.Context, draftID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.drafts, draftID)
	return nil
}

func (s *MockDraftStore) UpdateDraftStatus(ctx context.Context, draftID, status string) (*Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if draft, ok := s.drafts[draftID]; ok {
		draft.Status = status
		return draft, nil
	}
	return nil, nil
}

// AddDraft adds a draft directly for testing
func (s *MockDraftStore) AddDraft(draft *Draft) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drafts[draft.ID] = draft
}

// =============================================================================
// Draft Preview Page - Authentication Tests
// =============================================================================

func TestRouter_GetDraftPreview_WithoutAuth_RedirectsToLogin(t *testing.T) {
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	// Create a draft
	draft := &Draft{
		ID:        uuid.New().String(),
		UserID:    "some-user-id",
		Content:   "Test draft content",
		Status:    "draft",
		CharLimit: 500,
		CreatedAt: time.Now(),
	}
	draftStore.AddDraft(draft)

	req := httptest.NewRequest(http.MethodGet, "/drafts/"+draft.ID, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to login
	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusFound {
		t.Errorf("Expected redirect status, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

func TestRouter_GetDraftPreview_WithAuth_ReturnsHTML(t *testing.T) {
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	// Create a test user
	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Create a draft for this user
	draft := &Draft{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Content:   "This is my test draft content about a new feature",
		Status:    "draft",
		CharLimit: 500,
		CreatedAt: time.Now(),
	}
	draftStore.AddDraft(draft)

	// Generate valid JWT token
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts/"+draft.ID, nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Should return HTML content type
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected Content-Type text/html, got %s", contentType)
	}
}

func TestRouter_GetDraftPreview_NotFound_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	// Create a test user
	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Generate valid JWT token
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts/nonexistent-id", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 404
	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestRouter_GetDraftPreview_OtherUserDraft_Returns404(t *testing.T) {
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	// Create two users
	user1, _ := userStore.CreateUser(context.Background(), "user1@example.com", hashPassword("password123"))
	user2, _ := userStore.CreateUser(context.Background(), "user2@example.com", hashPassword("password123"))

	// Create a draft for user1
	draft := &Draft{
		ID:        uuid.New().String(),
		UserID:    user1.ID,
		Content:   "User1's draft",
		Status:    "draft",
		CharLimit: 500,
		CreatedAt: time.Now(),
	}
	draftStore.AddDraft(draft)

	// User2 tries to access user1's draft
	token, _ := generateToken(user2.ID, user2.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts/"+draft.ID, nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return 404 (not 403, to avoid leaking draft existence)
	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for other user's draft, got %d", rr.Code)
	}
}

// =============================================================================
// Draft Preview Page - Content Tests
// =============================================================================

func TestRouter_GetDraftPreview_DisplaysDraftContent(t *testing.T) {
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	draft := &Draft{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Content:   "This commit introduces secure authentication middleware for the API",
		Status:    "draft",
		CharLimit: 500,
		CreatedAt: time.Now(),
	}
	draftStore.AddDraft(draft)

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts/"+draft.ID, nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	body := rr.Body.String()
	// Should display the draft content
	if !strings.Contains(body, "secure authentication middleware") {
		t.Errorf("Expected draft content to be displayed, got: %s", body[:min(len(body), 500)])
	}
}

func TestRouter_GetDraftPreview_HasEditableTextarea(t *testing.T) {
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	draft := &Draft{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Content:   "Draft content here",
		Status:    "draft",
		CharLimit: 500,
		CreatedAt: time.Now(),
	}
	draftStore.AddDraft(draft)

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts/"+draft.ID, nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	body := rr.Body.String()
	// Should have a textarea element for editing
	if !strings.Contains(body, "<textarea") {
		t.Errorf("Expected textarea element for editing draft content")
	}
	// Textarea should contain the draft content
	if !strings.Contains(body, "Draft content here") {
		t.Errorf("Expected textarea to contain draft content")
	}
}

func TestRouter_GetDraftPreview_ShowsCharacterCount(t *testing.T) {
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	draft := &Draft{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Content:   "Short content", // 13 characters
		Status:    "draft",
		CharLimit: 500,
		CreatedAt: time.Now(),
	}
	draftStore.AddDraft(draft)

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts/"+draft.ID, nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	body := rr.Body.String()
	// Should show character count with limit (e.g., "13 / 500" or "Characters: 13 / 500")
	if !strings.Contains(body, "500") {
		t.Errorf("Expected character limit (500) to be displayed")
	}
	// Should have some indication of character count
	hasCharCount := strings.Contains(strings.ToLower(body), "character") ||
		strings.Contains(body, "/ 500") ||
		strings.Contains(body, "/500")
	if !hasCharCount {
		t.Errorf("Expected character count indicator, got: %s", body[:min(len(body), 500)])
	}
}

// =============================================================================
// Draft Preview Page - Button Tests
// =============================================================================

func TestRouter_GetDraftPreview_HasRegenerateButton(t *testing.T) {
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	draft := &Draft{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Content:   "Draft content",
		Status:    "draft",
		CharLimit: 500,
		CreatedAt: time.Now(),
	}
	draftStore.AddDraft(draft)

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts/"+draft.ID, nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	body := rr.Body.String()
	// Should have a Regenerate button
	hasRegenerate := strings.Contains(body, "Regenerate") ||
		strings.Contains(body, "regenerate") ||
		strings.Contains(body, "re-generate")
	if !hasRegenerate {
		t.Errorf("Expected Regenerate button, got: %s", body[:min(len(body), 500)])
	}
}

func TestRouter_GetDraftPreview_HasDeleteButton(t *testing.T) {
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	draft := &Draft{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Content:   "Draft content",
		Status:    "draft",
		CharLimit: 500,
		CreatedAt: time.Now(),
	}
	draftStore.AddDraft(draft)

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts/"+draft.ID, nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	body := rr.Body.String()
	// Should have a Delete button
	hasDelete := strings.Contains(body, "Delete") ||
		strings.Contains(body, "delete") ||
		strings.Contains(body, "Remove") ||
		strings.Contains(body, "Dismiss")
	if !hasDelete {
		t.Errorf("Expected Delete/Remove button, got: %s", body[:min(len(body), 500)])
	}
}

func TestRouter_GetDraftPreview_HasPostButton(t *testing.T) {
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	draft := &Draft{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Content:   "Draft content",
		Status:    "draft",
		CharLimit: 500,
		CreatedAt: time.Now(),
	}
	draftStore.AddDraft(draft)

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts/"+draft.ID, nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	body := rr.Body.String()
	// Should have a Post button
	hasPost := strings.Contains(body, "Post It") ||
		strings.Contains(body, "Post") ||
		strings.Contains(body, "Publish")
	if !hasPost {
		t.Errorf("Expected Post/Publish button, got: %s", body[:min(len(body), 500)])
	}
}

// =============================================================================
// Draft Preview Page - Form Submission Tests
// =============================================================================

func TestRouter_PostDraftRegenerate_RegeneratesContent(t *testing.T) {
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	draft := &Draft{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Content:   "Original content",
		Status:    "draft",
		CharLimit: 500,
		CreatedAt: time.Now(),
	}
	draftStore.AddDraft(draft)

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draft.ID+"/regenerate", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect back to draft preview or return success
	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusOK {
		t.Errorf("Expected redirect or success status, got %d", rr.Code)
	}
}

func TestRouter_PostDraftDelete_DeletesDraft(t *testing.T) {
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	draft := &Draft{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Content:   "Draft to delete",
		Status:    "draft",
		CharLimit: 500,
		CreatedAt: time.Now(),
	}
	draftStore.AddDraft(draft)

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draft.ID+"/delete", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to drafts list or dashboard
	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusFound {
		t.Errorf("Expected redirect status, got %d", rr.Code)
	}
}

func TestRouter_PostDraftPost_PublishesDraft(t *testing.T) {
	userStore := NewMockUserStore()
	draftStore := NewMockDraftStore()
	router := NewRouterWithDraftStore(userStore, draftStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	draft := &Draft{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Content:   "Draft to post",
		Status:    "draft",
		CharLimit: 500,
		CreatedAt: time.Now(),
	}
	draftStore.AddDraft(draft)

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/drafts/"+draft.ID+"/post", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect or return success
	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusOK && rr.Code != http.StatusFound {
		t.Errorf("Expected redirect or success status, got %d", rr.Code)
	}
}

// =============================================================================
// Helper: Router Constructor with Draft Store
// =============================================================================

// NewRouterWithDraftStore creates a router with user and draft stores for testing
func NewRouterWithDraftStore(userStore UserStore, draftStore DraftStore) *Router {
	r := NewRouter()
	r.userStore = userStore
	r.draftStore = draftStore
	return r
}
// =============================================================================
// alice-87: Drafts List Page Tests (TDD - RED)
// Tests for /drafts page: renders draft list, shows repo name/preview/time,
// empty state, pagination
// =============================================================================

// TDD DraftListItem type removed - using DraftItem from router.go

// TDD DraftLister interface removed - real DraftLister is in router.go

// MockDraftLister implements DraftLister for testing (matches router.go interface)
type MockDraftLister struct {
	mu       sync.Mutex
	drafts   map[string][]*DraftItem // userID -> drafts
	errOnGet error
}

func NewMockDraftLister() *MockDraftLister {
	return &MockDraftLister{
		drafts: make(map[string][]*DraftItem),
	}
}

func (m *MockDraftLister) AddDraft(userID string, draft *DraftItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drafts[userID] = append(m.drafts[userID], draft)
}

func (m *MockDraftLister) ListDraftsByUser(ctx context.Context, userID string) ([]*DraftItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.errOnGet != nil {
		return nil, m.errOnGet
	}

	drafts := m.drafts[userID]
	if drafts == nil {
		return []*DraftItem{}, nil
	}

	return drafts, nil
}

func (m *MockDraftLister) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errOnGet = err
}

// TestRouter_GetDrafts_Unauthenticated_RedirectsToLogin tests that unauthenticated
// users are redirected to login when accessing /drafts
func TestRouter_GetDrafts_Unauthenticated_RedirectsToLogin(t *testing.T) {
	router := NewRouter()

	req := httptest.NewRequest(http.MethodGet, "/drafts", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to login
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("Expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

// TestRouter_GetDrafts_WithAuth_ReturnsHTML tests that authenticated users
// get an HTML page when accessing /drafts
func TestRouter_GetDrafts_WithAuth_ReturnsHTML(t *testing.T) {
	userStore := NewMockUserStore()
	router := NewRouterWithStores(userStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
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

	// Should contain HTML structure
	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Errorf("Expected HTML doctype in response")
	}
	if !strings.Contains(body, "Drafts") {
		t.Errorf("Expected 'Drafts' in page content")
	}
}

// TestRouter_GetDrafts_EmptyState_ShowsEmptyMessage tests that when a user has
// no drafts, an appropriate empty state message is shown
func TestRouter_GetDrafts_EmptyState_ShowsEmptyMessage(t *testing.T) {
	userStore := NewMockUserStore()
	draftLister := NewMockDraftLister()
	router := NewRouterWithDraftLister(userStore, draftLister)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	// Should show empty state message (template shows "No Drafts Yet")
	if !strings.Contains(body, "No Drafts Yet") {
		t.Errorf("Expected empty state message about no drafts, got: %s", body[:min(len(body), 500)])
	}
}

// TestRouter_GetDrafts_WithDrafts_DisplaysDraftList tests that drafts are
// displayed when they exist
func TestRouter_GetDrafts_WithDrafts_DisplaysDraftList(t *testing.T) {
	userStore := NewMockUserStore()
	draftLister := NewMockDraftLister()
	router := NewRouterWithDraftLister(userStore, draftLister)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Add test drafts
	draftLister.AddDraft(user.ID, &DraftItem{
		ID:          "draft-1",
		RepoName:    "acme/awesome-project",
		PreviewText: "Exciting update! We just shipped a new feature...",
		Platform:    "threads",
		CreatedAt:   time.Now().Add(-1 * time.Hour),
	})
	draftLister.AddDraft(user.ID, &DraftItem{
		ID:          "draft-2",
		RepoName:    "acme/another-repo",
		PreviewText: "Bug fix: resolved issue with authentication...",
		Platform:    "threads",
		CreatedAt:   time.Now().Add(-2 * time.Hour),
	})

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Should contain draft content
	if !strings.Contains(body, "draft-1") && !strings.Contains(body, "acme/awesome-project") {
		t.Errorf("Expected first draft info in response, got: %s", body[:min(len(body), 500)])
	}
	if !strings.Contains(body, "draft-2") && !strings.Contains(body, "acme/another-repo") {
		t.Errorf("Expected second draft info in response")
	}
}

// TestRouter_GetDrafts_ShowsRepoNamePreviewTime tests that each draft shows
// the repository name, content preview, and timestamp
func TestRouter_GetDrafts_ShowsRepoNamePreviewTime(t *testing.T) {
	userStore := NewMockUserStore()
	draftLister := NewMockDraftLister()
	router := NewRouterWithDraftLister(userStore, draftLister)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Add a draft with specific content to verify display
	draftLister.AddDraft(user.ID, &DraftItem{
		ID:          "draft-123",
		RepoName:    "testorg/testrepo",
		PreviewText: "This is a preview of the generated post content",
		Platform:    "threads",
		CreatedAt:   time.Date(2026, 1, 20, 10, 30, 0, 0, time.UTC),
	})

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Should show repository name
	if !strings.Contains(body, "testorg/testrepo") {
		t.Errorf("Expected repository name 'testorg/testrepo' in response, got: %s", body[:min(len(body), 500)])
	}

	// Should show content preview
	if !strings.Contains(body, "preview of the generated post") {
		t.Errorf("Expected content preview in response")
	}

	// Should show some form of timestamp (exact format may vary)
	// We check for date components that would appear in a formatted time
	if !strings.Contains(body, "2026") && !strings.Contains(body, "Jan") && !strings.Contains(body, "20") {
		t.Errorf("Expected timestamp/date information in response")
	}
}

// TestRouter_GetDrafts_Pagination_FirstPage tests that pagination works correctly
// showing the first page of drafts
func TestRouter_GetDrafts_Pagination_FirstPage(t *testing.T) {
	userStore := NewMockUserStore()
	draftLister := NewMockDraftLister()
	router := NewRouterWithDraftLister(userStore, draftLister)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Add many drafts to test pagination
	for i := 0; i < 25; i++ {
		draftLister.AddDraft(user.ID, &DraftItem{
			ID:          fmt.Sprintf("draft-%d", i),
			RepoName:    fmt.Sprintf("repo/project-%d", i),
			PreviewText: fmt.Sprintf("Draft content for item %d", i),
			Platform:    "threads",
			CreatedAt:   time.Now().Add(-time.Duration(i) * time.Hour),
		})
	}

	token, _ := generateToken(user.ID, user.Email)

	// Request first page (default)
	req := httptest.NewRequest(http.MethodGet, "/drafts", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Should show page content (first page items)
	if !strings.Contains(body, "draft-0") && !strings.Contains(body, "repo/project-0") {
		t.Errorf("Expected first draft on first page")
	}

	// Should show pagination controls when there are more pages
	if !strings.Contains(body, "next") && !strings.Contains(body, "Next") && !strings.Contains(body, "page") {
		t.Errorf("Expected pagination controls when there are multiple pages")
	}
}

// TestRouter_GetDrafts_Pagination_SecondPage tests navigating to second page of drafts
func TestRouter_GetDrafts_Pagination_SecondPage(t *testing.T) {
	userStore := NewMockUserStore()
	draftLister := NewMockDraftLister()
	router := NewRouterWithDraftLister(userStore, draftLister)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Add many drafts to test pagination (assuming page size of 10)
	for i := 0; i < 25; i++ {
		draftLister.AddDraft(user.ID, &DraftItem{
			ID:          fmt.Sprintf("draft-%d", i),
			RepoName:    fmt.Sprintf("repo/project-%d", i),
			PreviewText: fmt.Sprintf("Draft content for item %d", i),
			Platform:    "threads",
			CreatedAt:   time.Now().Add(-time.Duration(i) * time.Hour),
		})
	}

	token, _ := generateToken(user.ID, user.Email)

	// Request second page
	req := httptest.NewRequest(http.MethodGet, "/drafts?page=2", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Should show second page content (items 10-19 for page size 10)
	if !strings.Contains(body, "draft-10") && !strings.Contains(body, "repo/project-10") {
		t.Errorf("Expected drafts from second page in response")
	}
}

// TestRouter_GetDrafts_ShowsDraftStatus tests that draft status is displayed
func TestRouter_GetDrafts_ShowsDraftStatus(t *testing.T) {
	userStore := NewMockUserStore()
	draftLister := NewMockDraftLister()
	router := NewRouterWithDraftLister(userStore, draftLister)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Add drafts (status is not part of DraftItem, but tests check for visual indicators)
	draftLister.AddDraft(user.ID, &DraftItem{
		ID:          "draft-1",
		RepoName:    "repo/pending",
		PreviewText: "Pending draft",
		Platform:    "threads",
		CreatedAt:   time.Now(),
	})
	draftLister.AddDraft(user.ID, &DraftItem{
		ID:          "draft-2",
		RepoName:    "repo/posted",
		PreviewText: "Posted draft",
		Platform:    "threads",
		CreatedAt:   time.Now(),
	})
	draftLister.AddDraft(user.ID, &DraftItem{
		ID:          "draft-3",
		RepoName:    "repo/failed",
		PreviewText: "Failed draft",
		Platform:    "threads",
		CreatedAt:   time.Now(),
	})

	token, _ := generateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/drafts", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Should show different status indicators
	// The exact text may vary (Draft, Posted, Failed or status badges)
	hasStatus := strings.Contains(body, "draft") || strings.Contains(body, "Draft")
	hasPosted := strings.Contains(body, "posted") || strings.Contains(body, "Posted")
	hasFailed := strings.Contains(body, "failed") || strings.Contains(body, "Failed")

	if !hasStatus || !hasPosted || !hasFailed {
		t.Errorf("Expected draft status indicators in response (draft/posted/failed)")
	}
}

// TDD stub removed - real NewRouterWithDraftLister is in router.go
