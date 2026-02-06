package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mikelady/roxas/internal/auth"
	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// TB-WEB-06 Tests: List Commits Endpoint (TDD - RED)
// =============================================================================

// MockCommitLister implements CommitLister for testing
type MockCommitLister struct {
	mu      sync.RWMutex
	commits map[string][]*services.Commit // userID -> commits
}

// NewMockCommitLister creates a new mock commit lister
func NewMockCommitLister() *MockCommitLister {
	return &MockCommitLister{
		commits: make(map[string][]*services.Commit),
	}
}

// ListCommitsByUser returns commits for a user
func (m *MockCommitLister) ListCommitsByUser(ctx context.Context, userID string) ([]*services.Commit, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if commits, ok := m.commits[userID]; ok {
		return commits, nil
	}
	return []*services.Commit{}, nil
}

// ErrorCommitLister always returns an error for testing error paths
type ErrorCommitLister struct {
	err error
}

func (e *ErrorCommitLister) ListCommitsByUser(ctx context.Context, userID string) ([]*services.Commit, error) {
	return nil, e.err
}

// AddCommitForUser adds a commit for testing
func (m *MockCommitLister) AddCommitForUser(userID string, commit *services.Commit) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if commit.ID == "" {
		commit.ID = uuid.New().String()
	}
	m.commits[userID] = append(m.commits[userID], commit)
}

// =============================================================================
// List Commits Tests
// =============================================================================

// TestListCommitsReturnsUserCommits tests that GET /api/v1/commits returns user's commits
func TestListCommitsReturnsUserCommits(t *testing.T) {
	commitLister := NewMockCommitLister()
	handler := NewCommitsHandler(commitLister)

	userID := "user-123"
	email := "test@example.com"

	// Pre-populate with commits for this user
	commitLister.AddCommitForUser(userID, &services.Commit{
		RepositoryID: "repo-1",
		CommitSHA:    "abc123",
		GitHubURL:    "https://github.com/user/repo/commit/abc123",
		Message:      "Add new feature",
		Author:       "testuser",
		Timestamp:    time.Now().Add(-1 * time.Hour),
	})
	commitLister.AddCommitForUser(userID, &services.Commit{
		RepositoryID: "repo-1",
		CommitSHA:    "def456",
		GitHubURL:    "https://github.com/user/repo/commit/def456",
		Message:      "Fix bug",
		Author:       "testuser",
		Timestamp:    time.Now(),
	})

	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/commits", nil, userID, email)
	rr := httptest.NewRecorder()

	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListCommits))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ListCommitsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(resp.Commits) != 2 {
		t.Errorf("Expected 2 commits, got %d", len(resp.Commits))
	}
}

// TestListCommitsNoAuth tests that unauthenticated requests return 401
func TestListCommitsNoAuth(t *testing.T) {
	commitLister := NewMockCommitLister()
	handler := NewCommitsHandler(commitLister)

	// Request WITHOUT Authorization header
	req := httptest.NewRequest(http.MethodGet, "/api/v1/commits", nil)

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListCommits))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestListCommitsOnlyReturnsOwnCommits tests that users only see their own commits
func TestListCommitsOnlyReturnsOwnCommits(t *testing.T) {
	commitLister := NewMockCommitLister()
	handler := NewCommitsHandler(commitLister)

	// Create commits for different users
	commitLister.AddCommitForUser("user-1", &services.Commit{
		CommitSHA: "commit-user1-a",
		GitHubURL: "https://github.com/user1/repo/commit/a",
		Message:   "User 1 commit A",
		Timestamp: time.Now(),
	})
	commitLister.AddCommitForUser("user-1", &services.Commit{
		CommitSHA: "commit-user1-b",
		GitHubURL: "https://github.com/user1/repo/commit/b",
		Message:   "User 1 commit B",
		Timestamp: time.Now(),
	})
	commitLister.AddCommitForUser("user-2", &services.Commit{
		CommitSHA: "commit-user2-a",
		GitHubURL: "https://github.com/user2/repo/commit/a",
		Message:   "User 2 commit A",
		Timestamp: time.Now(),
	})

	// User 1 should only see their 2 commits
	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/commits", nil, "user-1", "user1@example.com")
	rr := httptest.NewRecorder()

	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListCommits))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ListCommitsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(resp.Commits) != 2 {
		t.Errorf("Expected 2 commits for user-1, got %d", len(resp.Commits))
	}
}

// TestListCommitsEmptyList tests that empty list is returned when user has no commits
func TestListCommitsEmptyList(t *testing.T) {
	commitLister := NewMockCommitLister()
	handler := NewCommitsHandler(commitLister)

	userID := "user-with-no-commits"
	email := "nocommits@example.com"

	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/commits", nil, userID, email)
	rr := httptest.NewRecorder()

	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListCommits))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ListCommitsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Commits == nil {
		t.Error("Expected empty array, got nil")
	}

	if len(resp.Commits) != 0 {
		t.Errorf("Expected 0 commits, got %d", len(resp.Commits))
	}
}

// TestListCommitsIncludesAllFields tests that response includes all required fields
func TestListCommitsIncludesAllFields(t *testing.T) {
	commitLister := NewMockCommitLister()
	handler := NewCommitsHandler(commitLister)

	userID := "user-123"
	email := "test@example.com"

	expectedTime := time.Date(2025, 11, 28, 12, 0, 0, 0, time.UTC)
	commitLister.AddCommitForUser(userID, &services.Commit{
		RepositoryID: "repo-xyz",
		CommitSHA:    "abc123def456",
		GitHubURL:    "https://github.com/user/repo/commit/abc123def456",
		Message:      "Implement new feature",
		Author:       "developer",
		Timestamp:    expectedTime,
	})

	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/commits", nil, userID, email)
	rr := httptest.NewRecorder()

	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListCommits))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ListCommitsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(resp.Commits) != 1 {
		t.Fatalf("Expected 1 commit, got %d", len(resp.Commits))
	}

	commit := resp.Commits[0]

	// Verify all required fields are present
	if commit.ID == "" {
		t.Error("Expected commit ID to be set")
	}
	if commit.SHA != "abc123def456" {
		t.Errorf("Expected SHA abc123def456, got %s", commit.SHA)
	}
	if commit.Message != "Implement new feature" {
		t.Errorf("Expected message 'Implement new feature', got %s", commit.Message)
	}
	if commit.Author != "developer" {
		t.Errorf("Expected author 'developer', got %s", commit.Author)
	}
	if commit.Timestamp == "" {
		t.Error("Expected timestamp to be set")
	}
	if commit.GitHubURL != "https://github.com/user/repo/commit/abc123def456" {
		t.Errorf("Expected GitHubURL, got %s", commit.GitHubURL)
	}
}

// TestListCommitsServiceError tests that commit listing errors return 500
func TestListCommitsServiceError(t *testing.T) {
	commitLister := &ErrorCommitLister{err: errors.New("database unavailable")}
	handler := NewCommitsHandler(commitLister)

	userID := "user-123"
	email := "test@example.com"

	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/commits", nil, userID, email)
	rr := httptest.NewRecorder()

	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListCommits))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Error != "failed to retrieve commits" {
		t.Errorf("Expected error 'failed to retrieve commits', got %q", resp.Error)
	}
}

// TestListCommitsContentType tests that response has JSON content type
func TestListCommitsContentType(t *testing.T) {
	commitLister := NewMockCommitLister()
	handler := NewCommitsHandler(commitLister)

	userID := "user-123"
	email := "test@example.com"

	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/commits", nil, userID, email)
	rr := httptest.NewRecorder()

	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListCommits))
	protectedHandler.ServeHTTP(rr, req)

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}
}
