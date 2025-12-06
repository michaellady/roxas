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
	router := NewRouterWithAllStores(userStore, repoStore, nil, nil)

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
	router := NewRouterWithAllStores(userStore, repoStore, commitLister, nil)

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
// =============================================================================

func TestWebUI_FullAuthenticationFlow(t *testing.T) {
	// Setup stores
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStoreForWeb()
	commitLister := NewMockCommitListerForWeb()
	router := NewRouterWithAllStores(userStore, repoStore, commitLister, nil)

	const testEmail = "integration-test@example.com"
	const testPassword = "securepassword123"

	// =========================================================================
	// Step 1: GET /signup → form renders
	// =========================================================================
	t.Log("Step 1: GET /signup - form renders")

	reqSignupGet := httptest.NewRequest(http.MethodGet, "/signup", nil)
	rrSignupGet := httptest.NewRecorder()
	router.ServeHTTP(rrSignupGet, reqSignupGet)

	if rrSignupGet.Code != http.StatusOK {
		t.Fatalf("Step 1 FAILED: Expected 200 OK for GET /signup, got %d", rrSignupGet.Code)
	}
	if !strings.Contains(rrSignupGet.Body.String(), "Sign") {
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

	reqSignupPost := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(signupForm.Encode()))
	reqSignupPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrSignupPost := httptest.NewRecorder()
	router.ServeHTTP(rrSignupPost, reqSignupPost)

	if rrSignupPost.Code != http.StatusSeeOther {
		t.Fatalf("Step 2 FAILED: Expected 303 redirect for POST /signup, got %d: %s", rrSignupPost.Code, rrSignupPost.Body.String())
	}
	if rrSignupPost.Header().Get("Location") != "/login" {
		t.Fatalf("Step 2 FAILED: Expected redirect to /login, got %s", rrSignupPost.Header().Get("Location"))
	}

	// Verify user was created in store
	user, _ := userStore.GetUserByEmail(context.Background(), testEmail)
	if user == nil {
		t.Fatalf("Step 2 FAILED: User was not created in store")
	}
	t.Log("Step 2 PASSED: User created and redirected to login")

	// =========================================================================
	// Step 3: GET /login → form renders
	// =========================================================================
	t.Log("Step 3: GET /login - form renders")

	reqLoginGet := httptest.NewRequest(http.MethodGet, "/login", nil)
	rrLoginGet := httptest.NewRecorder()
	router.ServeHTTP(rrLoginGet, reqLoginGet)

	if rrLoginGet.Code != http.StatusOK {
		t.Fatalf("Step 3 FAILED: Expected 200 OK for GET /login, got %d", rrLoginGet.Code)
	}
	if !strings.Contains(strings.ToLower(rrLoginGet.Body.String()), "login") {
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

	reqLoginPost := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(loginForm.Encode()))
	reqLoginPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrLoginPost := httptest.NewRecorder()
	router.ServeHTTP(rrLoginPost, reqLoginPost)

	if rrLoginPost.Code != http.StatusSeeOther {
		t.Fatalf("Step 4 FAILED: Expected 303 redirect for POST /login, got %d: %s", rrLoginPost.Code, rrLoginPost.Body.String())
	}
	if rrLoginPost.Header().Get("Location") != "/dashboard" {
		t.Fatalf("Step 4 FAILED: Expected redirect to /dashboard, got %s", rrLoginPost.Header().Get("Location"))
	}

	// Extract auth cookie
	var authCookie *http.Cookie
	for _, c := range rrLoginPost.Result().Cookies() {
		if c.Name == "auth_token" {
			authCookie = c
			break
		}
	}
	if authCookie == nil || authCookie.Value == "" {
		t.Fatalf("Step 4 FAILED: Expected auth_token cookie to be set")
	}
	t.Log("Step 4 PASSED: Logged in, cookie set, redirected to dashboard")

	// =========================================================================
	// Step 5: GET /dashboard → shows empty state (no repos/commits yet)
	// =========================================================================
	t.Log("Step 5: GET /dashboard - shows empty state")

	reqDashEmpty := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	reqDashEmpty.AddCookie(authCookie)
	rrDashEmpty := httptest.NewRecorder()
	router.ServeHTTP(rrDashEmpty, reqDashEmpty)

	if rrDashEmpty.Code != http.StatusOK {
		t.Fatalf("Step 5 FAILED: Expected 200 OK for GET /dashboard, got %d", rrDashEmpty.Code)
	}
	dashBody := rrDashEmpty.Body.String()
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

	reqDashWithData := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	reqDashWithData.AddCookie(authCookie)
	rrDashWithData := httptest.NewRecorder()
	router.ServeHTTP(rrDashWithData, reqDashWithData)

	if rrDashWithData.Code != http.StatusOK {
		t.Fatalf("Step 7 FAILED: Expected 200 OK, got %d", rrDashWithData.Code)
	}
	dashWithDataBody := rrDashWithData.Body.String()
	if !strings.Contains(dashWithDataBody, "Add awesome new feature") {
		t.Fatalf("Step 7 FAILED: Expected commit message to be displayed, got: %s", dashWithDataBody[:min(len(dashWithDataBody), 500)])
	}
	t.Log("Step 7 PASSED: Dashboard shows commit")

	// =========================================================================
	// Step 8: POST /logout → cookie cleared, redirect to /login
	// =========================================================================
	t.Log("Step 8: POST /logout - cookie cleared, redirect to /login")

	reqLogout := httptest.NewRequest(http.MethodPost, "/logout", nil)
	reqLogout.AddCookie(authCookie)
	rrLogout := httptest.NewRecorder()
	router.ServeHTTP(rrLogout, reqLogout)

	if rrLogout.Code != http.StatusSeeOther {
		t.Fatalf("Step 8 FAILED: Expected 303 redirect, got %d", rrLogout.Code)
	}
	if rrLogout.Header().Get("Location") != "/login" {
		t.Fatalf("Step 8 FAILED: Expected redirect to /login, got %s", rrLogout.Header().Get("Location"))
	}

	// Verify cookie is cleared
	var clearedCookie *http.Cookie
	for _, c := range rrLogout.Result().Cookies() {
		if c.Name == "auth_token" {
			clearedCookie = c
			break
		}
	}
	if clearedCookie == nil {
		t.Fatalf("Step 8 FAILED: Expected auth_token cookie in response")
	}
	if clearedCookie.MaxAge >= 0 && clearedCookie.Value != "" {
		t.Fatalf("Step 8 FAILED: Cookie should be cleared (MaxAge<0 or empty value)")
	}
	t.Log("Step 8 PASSED: Logged out, cookie cleared")

	// =========================================================================
	// Step 9: GET /dashboard → redirects to /login (not authenticated)
	// =========================================================================
	t.Log("Step 9: GET /dashboard without auth - redirects to /login")

	reqDashNoAuth := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	// No cookie attached
	rrDashNoAuth := httptest.NewRecorder()
	router.ServeHTTP(rrDashNoAuth, reqDashNoAuth)

	if rrDashNoAuth.Code != http.StatusSeeOther {
		t.Fatalf("Step 9 FAILED: Expected 303 redirect, got %d", rrDashNoAuth.Code)
	}
	if rrDashNoAuth.Header().Get("Location") != "/login" {
		t.Fatalf("Step 9 FAILED: Expected redirect to /login, got %s", rrDashNoAuth.Header().Get("Location"))
	}
	t.Log("Step 9 PASSED: Unauthenticated dashboard access redirects to login")

	t.Log("=== ALL 9 STEPS PASSED: Full authentication flow verified ===")
}
