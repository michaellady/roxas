package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mikelady/roxas/internal/auth"
)

// =============================================================================
// Mock Secret Generator (for deterministic testing)
// =============================================================================

// MockSecretGenerator returns a fixed secret for testing
type MockSecretGenerator struct {
	Secret string
}

func (m *MockSecretGenerator) Generate() (string, error) {
	return m.Secret, nil
}

// =============================================================================
// Test Helper: Create authenticated request
// =============================================================================

func createAuthenticatedRequest(t *testing.T, method, path string, body []byte, userID, email string) *http.Request {
	t.Helper()

	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("Content-Type", "application/json")

	// Generate JWT token for the user
	token, err := auth.GenerateToken(userID, email)
	if err != nil {
		t.Fatalf("Failed to generate JWT token: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	return req
}

// =============================================================================
// TB10 Tests: Add Repository Endpoint (TDD - RED)
// =============================================================================

// TestAddRepositoryValidGitHubURL tests successful repository creation with valid GitHub URL
func TestAddRepositoryValidGitHubURL(t *testing.T) {
	store := NewMockRepositoryStore()
	secretGen := &MockSecretGenerator{Secret: "test-webhook-secret-12345"}
	handler := NewRepositoryHandler(store, secretGen, "https://api.roxas.dev")

	userID := "user-123"
	email := "test@example.com"

	reqBody := AddRepositoryRequest{
		GitHubURL: "https://github.com/michaellady/roxas",
	}
	body, _ := json.Marshal(reqBody)

	req := createAuthenticatedRequest(t, http.MethodPost, "/api/v1/repositories", body, userID, email)

	rr := httptest.NewRecorder()

	// Wrap handler with JWT middleware to extract user context
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.AddRepository))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status 201 Created, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp AddRepositoryResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Validate repository object
	if resp.Repository.ID == "" {
		t.Error("Expected repository ID to be set")
	}
	if resp.Repository.GitHubURL != reqBody.GitHubURL {
		t.Errorf("Expected github_url %s, got %s", reqBody.GitHubURL, resp.Repository.GitHubURL)
	}
	if resp.Repository.UserID != userID {
		t.Errorf("Expected user_id %s, got %s", userID, resp.Repository.UserID)
	}

	// Validate webhook config
	if resp.Webhook.URL == "" {
		t.Error("Expected webhook URL to be set")
	}
	if !strings.Contains(resp.Webhook.URL, "api.roxas.dev") {
		t.Errorf("Expected webhook URL to contain API domain, got %s", resp.Webhook.URL)
	}
	if resp.Webhook.Secret != secretGen.Secret {
		t.Errorf("Expected webhook secret %s, got %s", secretGen.Secret, resp.Webhook.Secret)
	}

	// Verify repository exists in store
	stored, _ := store.GetRepositoryByUserAndURL(context.Background(), userID, reqBody.GitHubURL)
	if stored == nil {
		t.Error("Expected repository to be stored in database")
	}
}

// TestAddRepositoryInvalidURLFormat tests various invalid URL formats return 400 Bad Request
func TestAddRepositoryInvalidURLFormat(t *testing.T) {
	store := NewMockRepositoryStore()
	secretGen := &MockSecretGenerator{Secret: "test-secret"}
	handler := NewRepositoryHandler(store, secretGen, "https://api.roxas.dev")

	userID := "user-123"
	email := "test@example.com"

	testCases := []struct {
		name      string
		githubURL string
	}{
		// Syntactically invalid URLs
		{"empty URL", ""},
		{"not a URL", "not-a-url"},
		{"missing protocol", "github.com/user/repo"},
		{"invalid protocol", "ftp://github.com/user/repo"},

		// Wrong hosts (not GitHub)
		{"gitlab URL", "https://gitlab.com/user/repo"},
		{"bitbucket URL", "https://bitbucket.org/user/repo"},
		{"random domain", "https://example.com/user/repo"},

		// Invalid GitHub URL formats
		{"github root", "https://github.com"},
		{"github user only", "https://github.com/user"},
		{"github with trailing slash only", "https://github.com/user/"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := AddRepositoryRequest{
				GitHubURL: tc.githubURL,
			}
			body, _ := json.Marshal(reqBody)

			req := createAuthenticatedRequest(t, http.MethodPost, "/api/v1/repositories", body, userID, email)

			rr := httptest.NewRecorder()
			protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.AddRepository))
			protectedHandler.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400 Bad Request for '%s', got %d: %s",
					tc.name, rr.Code, rr.Body.String())
			}

			var errResp ErrorResponse
			if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
				t.Fatalf("Failed to decode error response: %v", err)
			}

			if errResp.Error == "" {
				t.Error("Expected error message in response")
			}
		})
	}
}

// TestAddRepositoryDuplicate tests that adding the same repo twice returns 409 Conflict
func TestAddRepositoryDuplicate(t *testing.T) {
	store := NewMockRepositoryStore()
	secretGen := &MockSecretGenerator{Secret: "test-secret"}
	handler := NewRepositoryHandler(store, secretGen, "https://api.roxas.dev")

	userID := "user-123"
	email := "test@example.com"
	githubURL := "https://github.com/michaellady/roxas"

	reqBody := AddRepositoryRequest{
		GitHubURL: githubURL,
	}
	body, _ := json.Marshal(reqBody)

	// First request - should succeed
	req1 := createAuthenticatedRequest(t, http.MethodPost, "/api/v1/repositories", body, userID, email)
	rr1 := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.AddRepository))
	protectedHandler.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusCreated {
		t.Fatalf("First request failed: %d: %s", rr1.Code, rr1.Body.String())
	}

	// Second request with same URL - should return 409
	body2, _ := json.Marshal(reqBody)
	req2 := createAuthenticatedRequest(t, http.MethodPost, "/api/v1/repositories", body2, userID, email)
	rr2 := httptest.NewRecorder()
	protectedHandler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusConflict {
		t.Errorf("Expected status 409 Conflict for duplicate repository, got %d: %s",
			rr2.Code, rr2.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr2.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errResp.Error == "" {
		t.Error("Expected error message in response")
	}
}

// TestAddRepositoryNoAuth tests that unauthenticated requests return 401 Unauthorized
func TestAddRepositoryNoAuth(t *testing.T) {
	store := NewMockRepositoryStore()
	secretGen := &MockSecretGenerator{Secret: "test-secret"}
	handler := NewRepositoryHandler(store, secretGen, "https://api.roxas.dev")

	reqBody := AddRepositoryRequest{
		GitHubURL: "https://github.com/michaellady/roxas",
	}
	body, _ := json.Marshal(reqBody)

	// Request WITHOUT Authorization header
	req := httptest.NewRequest(http.MethodPost, "/api/v1/repositories", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	// JWT middleware should reject this
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.AddRepository))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d: %s", rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errResp.Error == "" {
		t.Error("Expected error message in response")
	}
}

// TestAddRepositoryDifferentUsersSameRepo tests that different users can add the same repo
func TestAddRepositoryDifferentUsersSameRepo(t *testing.T) {
	store := NewMockRepositoryStore()
	secretGen := &MockSecretGenerator{Secret: "test-secret"}
	handler := NewRepositoryHandler(store, secretGen, "https://api.roxas.dev")

	githubURL := "https://github.com/michaellady/roxas"

	reqBody := AddRepositoryRequest{
		GitHubURL: githubURL,
	}
	body, _ := json.Marshal(reqBody)

	// User 1 adds the repo
	req1 := createAuthenticatedRequest(t, http.MethodPost, "/api/v1/repositories", body, "user-1", "user1@example.com")
	rr1 := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.AddRepository))
	protectedHandler.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusCreated {
		t.Fatalf("User 1 request failed: %d: %s", rr1.Code, rr1.Body.String())
	}

	// User 2 adds the same repo - should also succeed
	body2, _ := json.Marshal(reqBody)
	req2 := createAuthenticatedRequest(t, http.MethodPost, "/api/v1/repositories", body2, "user-2", "user2@example.com")
	rr2 := httptest.NewRecorder()
	protectedHandler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusCreated {
		t.Errorf("Expected status 201 Created for different user, got %d: %s",
			rr2.Code, rr2.Body.String())
	}
}

// TestAddRepositoryReturnsCorrectContentType tests that response has JSON content type
func TestAddRepositoryReturnsCorrectContentType(t *testing.T) {
	store := NewMockRepositoryStore()
	secretGen := &MockSecretGenerator{Secret: "test-secret"}
	handler := NewRepositoryHandler(store, secretGen, "https://api.roxas.dev")

	userID := "user-123"
	email := "test@example.com"

	reqBody := AddRepositoryRequest{
		GitHubURL: "https://github.com/michaellady/roxas",
	}
	body, _ := json.Marshal(reqBody)

	req := createAuthenticatedRequest(t, http.MethodPost, "/api/v1/repositories", body, userID, email)

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.AddRepository))
	protectedHandler.ServeHTTP(rr, req)

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}
}

// TestAddRepositoryMissingBody tests that missing request body returns 400 Bad Request
func TestAddRepositoryMissingBody(t *testing.T) {
	store := NewMockRepositoryStore()
	secretGen := &MockSecretGenerator{Secret: "test-secret"}
	handler := NewRepositoryHandler(store, secretGen, "https://api.roxas.dev")

	userID := "user-123"
	email := "test@example.com"

	testCases := []struct {
		name string
		body string
	}{
		{"empty body", ``},
		{"empty JSON", `{}`},
		{"invalid JSON", `{invalid}`},
		{"missing github_url", `{"other_field": "value"}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.body == "" {
				req = createAuthenticatedRequest(t, http.MethodPost, "/api/v1/repositories", nil, userID, email)
			} else {
				req = createAuthenticatedRequest(t, http.MethodPost, "/api/v1/repositories", []byte(tc.body), userID, email)
			}

			rr := httptest.NewRecorder()
			protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.AddRepository))
			protectedHandler.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400 Bad Request for %s, got %d: %s",
					tc.name, rr.Code, rr.Body.String())
			}
		})
	}
}

// =============================================================================
// TB-WEB-05 Tests: List Repositories Endpoint (TDD - RED -> GREEN)
// =============================================================================

// TestListRepositoriesReturnsUserRepos tests that GET /api/v1/repositories returns user's repositories
func TestListRepositoriesReturnsUserRepos(t *testing.T) {
	store := NewMockRepositoryStore()
	secretGen := &MockSecretGenerator{Secret: "test-webhook-secret"}
	handler := NewRepositoryHandler(store, secretGen, "https://api.roxas.dev")

	userID := "user-123"
	email := "test@example.com"

	// Pre-populate store with repositories for this user
	store.CreateRepository(context.Background(), userID, "https://github.com/user/repo1", "secret1")
	store.CreateRepository(context.Background(), userID, "https://github.com/user/repo2", "secret2")

	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/repositories", nil, userID, email)
	rr := httptest.NewRecorder()

	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListRepositories))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ListRepositoriesResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(resp.Repositories) != 2 {
		t.Errorf("Expected 2 repositories, got %d", len(resp.Repositories))
	}

	// Verify user_id matches
	for _, repo := range resp.Repositories {
		if repo.UserID != userID {
			t.Errorf("Expected user_id %s, got %s", userID, repo.UserID)
		}
	}
}

// TestListRepositoriesExcludesWebhookSecret tests that webhook_secret is NOT included in response
func TestListRepositoriesExcludesWebhookSecret(t *testing.T) {
	store := NewMockRepositoryStore()
	secretGen := &MockSecretGenerator{Secret: "test-webhook-secret"}
	handler := NewRepositoryHandler(store, secretGen, "https://api.roxas.dev")

	userID := "user-123"
	email := "test@example.com"

	// Pre-populate store with a repository
	store.CreateRepository(context.Background(), userID, "https://github.com/user/repo1", "super-secret-value")

	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/repositories", nil, userID, email)
	rr := httptest.NewRecorder()

	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListRepositories))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	// Check raw JSON does not contain webhook_secret
	body := rr.Body.String()
	if strings.Contains(body, "webhook_secret") || strings.Contains(body, "super-secret-value") {
		t.Errorf("Response should NOT contain webhook_secret, got: %s", body)
	}
}

// TestListRepositoriesNoAuth tests that unauthenticated requests return 401
func TestListRepositoriesNoAuth(t *testing.T) {
	store := NewMockRepositoryStore()
	secretGen := &MockSecretGenerator{Secret: "test-secret"}
	handler := NewRepositoryHandler(store, secretGen, "https://api.roxas.dev")

	// Request WITHOUT Authorization header
	req := httptest.NewRequest(http.MethodGet, "/api/v1/repositories", nil)

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListRepositories))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestListRepositoriesOnlyReturnsOwnRepos tests that users only see their own repositories
func TestListRepositoriesOnlyReturnsOwnRepos(t *testing.T) {
	store := NewMockRepositoryStore()
	secretGen := &MockSecretGenerator{Secret: "test-secret"}
	handler := NewRepositoryHandler(store, secretGen, "https://api.roxas.dev")

	// Create repos for different users
	store.CreateRepository(context.Background(), "user-1", "https://github.com/user1/repo1", "secret1")
	store.CreateRepository(context.Background(), "user-1", "https://github.com/user1/repo2", "secret2")
	store.CreateRepository(context.Background(), "user-2", "https://github.com/user2/repo3", "secret3")

	// User 1 should only see their 2 repos
	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/repositories", nil, "user-1", "user1@example.com")
	rr := httptest.NewRecorder()

	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListRepositories))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ListRepositoriesResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(resp.Repositories) != 2 {
		t.Errorf("Expected 2 repositories for user-1, got %d", len(resp.Repositories))
	}

	// Verify all returned repos belong to user-1
	for _, repo := range resp.Repositories {
		if repo.UserID != "user-1" {
			t.Errorf("Expected user_id user-1, got %s", repo.UserID)
		}
	}
}

// TestListRepositoriesEmptyList tests that empty list is returned when user has no repos
func TestListRepositoriesEmptyList(t *testing.T) {
	store := NewMockRepositoryStore()
	secretGen := &MockSecretGenerator{Secret: "test-secret"}
	handler := NewRepositoryHandler(store, secretGen, "https://api.roxas.dev")

	userID := "user-with-no-repos"
	email := "noreps@example.com"

	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/repositories", nil, userID, email)
	rr := httptest.NewRecorder()

	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListRepositories))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ListRepositoriesResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Repositories == nil {
		t.Error("Expected empty array, got nil")
	}

	if len(resp.Repositories) != 0 {
		t.Errorf("Expected 0 repositories, got %d", len(resp.Repositories))
	}
}
