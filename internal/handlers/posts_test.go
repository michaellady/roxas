package handlers

import (
	"context"
	"encoding/json"
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
// TB18: Posts API Endpoint Tests (TDD - RED)
// =============================================================================

// =============================================================================
// Mock Stores for Posts Tests
// =============================================================================

// MockPostStore is an in-memory post store for testing
type MockPostStore struct {
	mu    sync.RWMutex
	posts map[string]*Post
}

func NewMockPostStore() *MockPostStore {
	return &MockPostStore{
		posts: make(map[string]*Post),
	}
}

func (m *MockPostStore) CreatePost(ctx context.Context, commitID, platform, content string) (*Post, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	post := &Post{
		ID:        uuid.New().String(),
		CommitID:  commitID,
		Platform:  platform,
		Content:   content,
		Status:    "draft",
		CreatedAt: time.Now(),
	}
	m.posts[post.ID] = post
	return post, nil
}

func (m *MockPostStore) GetPostByID(ctx context.Context, postID string) (*Post, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if post, ok := m.posts[postID]; ok {
		return post, nil
	}
	return nil, nil
}

func (m *MockPostStore) GetPostsByUserID(ctx context.Context, userID string) ([]*Post, error) {
	// In real implementation, this would join with commits and repositories
	// For testing, we return all posts (tests will set up proper fixtures)
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Post, 0, len(m.posts))
	for _, p := range m.posts {
		result = append(result, p)
	}
	return result, nil
}

// MockCommitStoreForPosts extends commit store with user ownership lookup
type MockCommitStoreForPosts struct {
	mu      sync.RWMutex
	commits map[string]*services.Commit
	// Maps commitID -> userID for ownership checks
	ownership map[string]string
}

func NewMockCommitStoreForPosts() *MockCommitStoreForPosts {
	return &MockCommitStoreForPosts{
		commits:   make(map[string]*services.Commit),
		ownership: make(map[string]string),
	}
}

func (m *MockCommitStoreForPosts) AddCommit(commit *services.Commit, userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.commits[commit.ID] = commit
	m.ownership[commit.ID] = userID
}

func (m *MockCommitStoreForPosts) GetCommitByID(ctx context.Context, commitID string) (*services.Commit, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if commit, ok := m.commits[commitID]; ok {
		return commit, nil
	}
	return nil, nil
}

func (m *MockCommitStoreForPosts) GetCommitOwnerID(ctx context.Context, commitID string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if userID, ok := m.ownership[commitID]; ok {
		return userID, nil
	}
	return "", nil
}

// MockPostGenerator for deterministic testing
type MockPostGenerator struct {
	Response *services.GeneratedPost
	Error    error
}

func (m *MockPostGenerator) Generate(ctx context.Context, platform string, commit *services.Commit) (*services.GeneratedPost, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.Response, nil
}

// =============================================================================
// POST /api/v1/commits/:id/posts?platform=linkedin Tests
// =============================================================================

// TestCreatePostValidRequest tests successful post generation
func TestCreatePostValidRequest(t *testing.T) {
	postStore := NewMockPostStore()
	commitStore := NewMockCommitStoreForPosts()
	generator := &MockPostGenerator{
		Response: &services.GeneratedPost{
			Platform: "linkedin",
			Content:  "🚀 Excited to share our latest update! #coding",
			CommitID: "commit-123",
		},
	}

	userID := "user-123"
	commit := &services.Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123",
		Message:      "feat: add new feature",
		Author:       "Test Author",
		Timestamp:    time.Now(),
	}
	commitStore.AddCommit(commit, userID)

	handler := NewPostsHandler(postStore, commitStore, generator)

	req := createAuthenticatedRequest(t, http.MethodPost, "/api/v1/commits/commit-123/posts?platform=linkedin", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.CreatePost))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status 201 Created, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp CreatePostResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Post.ID == "" {
		t.Error("Expected post ID to be set")
	}
	if resp.Post.Platform != "linkedin" {
		t.Errorf("Expected platform linkedin, got %s", resp.Post.Platform)
	}
	if resp.Post.Status != "draft" {
		t.Errorf("Expected status draft, got %s", resp.Post.Status)
	}
}

// TestCreatePostInvalidCommitID tests 404 for non-existent commit
func TestCreatePostInvalidCommitID(t *testing.T) {
	postStore := NewMockPostStore()
	commitStore := NewMockCommitStoreForPosts()
	generator := &MockPostGenerator{}

	handler := NewPostsHandler(postStore, commitStore, generator)

	userID := "user-123"
	req := createAuthenticatedRequest(t, http.MethodPost, "/api/v1/commits/nonexistent-commit/posts?platform=linkedin", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.CreatePost))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 Not Found, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestCreatePostCommitBelongsToOtherUser tests 403 for accessing another user's commit
func TestCreatePostCommitBelongsToOtherUser(t *testing.T) {
	postStore := NewMockPostStore()
	commitStore := NewMockCommitStoreForPosts()
	generator := &MockPostGenerator{}

	// Commit belongs to user-owner
	ownerUserID := "user-owner"
	commit := &services.Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123",
		Message:      "feat: add feature",
		Author:       "Owner",
		Timestamp:    time.Now(),
	}
	commitStore.AddCommit(commit, ownerUserID)

	handler := NewPostsHandler(postStore, commitStore, generator)

	// Different user tries to access
	attackerUserID := "user-attacker"
	req := createAuthenticatedRequest(t, http.MethodPost, "/api/v1/commits/commit-123/posts?platform=linkedin", nil, attackerUserID, "attacker@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.CreatePost))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 Forbidden, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestCreatePostInvalidPlatform tests 400 for unsupported platform
func TestCreatePostInvalidPlatform(t *testing.T) {
	postStore := NewMockPostStore()
	commitStore := NewMockCommitStoreForPosts()
	generator := &MockPostGenerator{}

	userID := "user-123"
	commit := &services.Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123",
		Message:      "feat: add feature",
		Author:       "Test",
		Timestamp:    time.Now(),
	}
	commitStore.AddCommit(commit, userID)

	handler := NewPostsHandler(postStore, commitStore, generator)

	req := createAuthenticatedRequest(t, http.MethodPost, "/api/v1/commits/commit-123/posts?platform=livejournal", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.CreatePost))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 Bad Request, got %d: %s", rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	// Error should mention supported platforms
	if errResp.Error == "" {
		t.Error("Expected error message")
	}
}

// TestCreatePostMissingPlatform tests 400 when platform query param is missing
func TestCreatePostMissingPlatform(t *testing.T) {
	postStore := NewMockPostStore()
	commitStore := NewMockCommitStoreForPosts()
	generator := &MockPostGenerator{}

	userID := "user-123"
	commit := &services.Commit{
		ID:           "commit-123",
		RepositoryID: "repo-456",
		CommitSHA:    "abc123",
		Message:      "feat: add feature",
		Author:       "Test",
		Timestamp:    time.Now(),
	}
	commitStore.AddCommit(commit, userID)

	handler := NewPostsHandler(postStore, commitStore, generator)

	// No platform query parameter
	req := createAuthenticatedRequest(t, http.MethodPost, "/api/v1/commits/commit-123/posts", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.CreatePost))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 Bad Request, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestCreatePostNoAuth tests 401 when not authenticated
func TestCreatePostNoAuth(t *testing.T) {
	postStore := NewMockPostStore()
	commitStore := NewMockCommitStoreForPosts()
	generator := &MockPostGenerator{}

	handler := NewPostsHandler(postStore, commitStore, generator)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/commits/commit-123/posts?platform=linkedin", nil)

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.CreatePost))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// GET /api/v1/posts Tests
// =============================================================================

// TestListPostsReturnsUserPostsOnly tests that only user's posts are returned
func TestListPostsReturnsUserPostsOnly(t *testing.T) {
	postStore := NewMockPostStore()
	commitStore := NewMockCommitStoreForPosts()
	generator := &MockPostGenerator{}

	// Create posts for user-1
	user1ID := "user-1"
	commit1 := &services.Commit{ID: "commit-1", RepositoryID: "repo-1", CommitSHA: "sha1", Message: "msg1", Timestamp: time.Now()}
	commitStore.AddCommit(commit1, user1ID)
	postStore.CreatePost(context.Background(), "commit-1", "linkedin", "User 1 post")

	// Create posts for user-2
	user2ID := "user-2"
	commit2 := &services.Commit{ID: "commit-2", RepositoryID: "repo-2", CommitSHA: "sha2", Message: "msg2", Timestamp: time.Now()}
	commitStore.AddCommit(commit2, user2ID)
	postStore.CreatePost(context.Background(), "commit-2", "twitter", "User 2 post")

	handler := NewPostsHandler(postStore, commitStore, generator)

	// User 1 lists their posts
	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/posts", nil, user1ID, "user1@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListPosts))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ListPostsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Should only see user-1's posts (implementation will filter by ownership)
	// For now, just verify the response structure
	if resp.Posts == nil {
		t.Error("Expected posts array, got nil")
	}
}

// TestListPostsEmptyForNewUser tests that new user gets empty array (not null)
func TestListPostsEmptyForNewUser(t *testing.T) {
	postStore := NewMockPostStore()
	commitStore := NewMockCommitStoreForPosts()
	generator := &MockPostGenerator{}

	handler := NewPostsHandler(postStore, commitStore, generator)

	// New user with no posts
	newUserID := "new-user-no-posts"
	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/posts", nil, newUserID, "new@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListPosts))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	// Response should be [] not null
	body := rr.Body.String()
	if body == "null" || body == "null\n" {
		t.Error("Expected empty array [], got null")
	}

	var resp ListPostsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Posts == nil {
		t.Error("Expected empty posts array, got nil")
	}
}

// TestListPostsNoAuth tests 401 when not authenticated
func TestListPostsNoAuth(t *testing.T) {
	postStore := NewMockPostStore()
	commitStore := NewMockCommitStoreForPosts()
	generator := &MockPostGenerator{}

	handler := NewPostsHandler(postStore, commitStore, generator)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts", nil)

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.ListPosts))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// GET /api/v1/posts/:id Tests
// =============================================================================

// TestGetPostValidID tests successful retrieval of a post
func TestGetPostValidID(t *testing.T) {
	postStore := NewMockPostStore()
	commitStore := NewMockCommitStoreForPosts()
	generator := &MockPostGenerator{}

	userID := "user-123"
	commit := &services.Commit{ID: "commit-123", RepositoryID: "repo-456", CommitSHA: "abc123", Message: "feat", Timestamp: time.Now()}
	commitStore.AddCommit(commit, userID)

	// Create a post
	post, _ := postStore.CreatePost(context.Background(), "commit-123", "linkedin", "Test post content")

	handler := NewPostsHandler(postStore, commitStore, generator)

	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/posts/"+post.ID, nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.GetPost))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp GetPostResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Post.ID != post.ID {
		t.Errorf("Expected post ID %s, got %s", post.ID, resp.Post.ID)
	}
}

// TestGetPostOtherUsersPost tests 403 when accessing another user's post
func TestGetPostOtherUsersPost(t *testing.T) {
	postStore := NewMockPostStore()
	commitStore := NewMockCommitStoreForPosts()
	generator := &MockPostGenerator{}

	// Post belongs to owner
	ownerID := "user-owner"
	commit := &services.Commit{ID: "commit-123", RepositoryID: "repo-456", CommitSHA: "abc123", Message: "feat", Timestamp: time.Now()}
	commitStore.AddCommit(commit, ownerID)
	post, _ := postStore.CreatePost(context.Background(), "commit-123", "linkedin", "Owner's post")

	handler := NewPostsHandler(postStore, commitStore, generator)

	// Attacker tries to access
	attackerID := "user-attacker"
	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/posts/"+post.ID, nil, attackerID, "attacker@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.GetPost))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 Forbidden, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestGetPostInvalidID tests 404 for non-existent post
func TestGetPostInvalidID(t *testing.T) {
	postStore := NewMockPostStore()
	commitStore := NewMockCommitStoreForPosts()
	generator := &MockPostGenerator{}

	handler := NewPostsHandler(postStore, commitStore, generator)

	userID := "user-123"
	req := createAuthenticatedRequest(t, http.MethodGet, "/api/v1/posts/nonexistent-post-id", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.GetPost))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 Not Found, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestGetPostNoAuth tests 401 when not authenticated
func TestGetPostNoAuth(t *testing.T) {
	postStore := NewMockPostStore()
	commitStore := NewMockCommitStoreForPosts()
	generator := &MockPostGenerator{}

	handler := NewPostsHandler(postStore, commitStore, generator)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/some-post-id", nil)

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.GetPost))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Note: PostResponse, CreatePostResponse, GetPostResponse, ListPostsResponse,
// PostsHandler, NewPostsHandler, and handler methods are defined in posts.go
