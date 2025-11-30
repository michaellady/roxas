package tests

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
	"github.com/mikelady/roxas/internal/auth"
	"github.com/mikelady/roxas/internal/handlers"
	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// Unified Integration Commit Store
// =============================================================================
// This store implements both handlers.CommitStore and handlers.CommitStoreForPosts
// to bridge between webhook handler (which stores commits) and posts handler
// (which retrieves commits for post generation).

// MockCommitStore implements both CommitStore and CommitStoreForPosts interfaces
type MockCommitStore struct {
	mu        sync.Mutex
	commits   map[string]*handlers.StoredCommit // key: "repoID:sha" or commitID
	ownership map[string]string                 // commitID -> userID
	repoStore *MockRepositoryStore
}

func NewMockCommitStore(repoStore *MockRepositoryStore) *MockCommitStore {
	return &MockCommitStore{
		commits:   make(map[string]*handlers.StoredCommit),
		ownership: make(map[string]string),
		repoStore: repoStore,
	}
}

// StoreCommit implements handlers.CommitStore
func (s *MockCommitStore) StoreCommit(ctx context.Context, commit *handlers.StoredCommit) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicate
	key := commit.RepositoryID + ":" + commit.CommitSHA
	if _, ok := s.commits[key]; ok {
		return nil // Already exists, skip
	}

	// Generate ID
	commit.ID = uuid.New().String()
	s.commits[key] = commit
	s.commits[commit.ID] = commit

	// Derive ownership from repository
	if s.repoStore != nil {
		repo, _ := s.repoStore.GetRepositoryByID(ctx, commit.RepositoryID)
		if repo != nil {
			s.ownership[commit.ID] = repo.UserID
		}
	}

	return nil
}

// GetCommitBySHA implements handlers.CommitStore
func (s *MockCommitStore) GetCommitBySHA(ctx context.Context, repoID, sha string) (*handlers.StoredCommit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := repoID + ":" + sha
	if commit, ok := s.commits[key]; ok {
		return commit, nil
	}
	return nil, nil
}

// GetCommitByID implements handlers.CommitStoreForPosts
func (s *MockCommitStore) GetCommitByID(ctx context.Context, commitID string) (*services.Commit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stored, ok := s.commits[commitID]; ok {
		// Convert handlers.StoredCommit to services.Commit
		return &services.Commit{
			ID:           stored.ID,
			RepositoryID: stored.RepositoryID,
			CommitSHA:    stored.CommitSHA,
			GitHubURL:    stored.GitHubURL,
			Message:      stored.Message,
			Author:       stored.Author,
			Timestamp:    stored.Timestamp,
			CreatedAt:    stored.Timestamp, // Use timestamp as created_at
		}, nil
	}
	return nil, nil
}

// GetCommitOwnerID implements handlers.CommitStoreForPosts
func (s *MockCommitStore) GetCommitOwnerID(ctx context.Context, commitID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if userID, ok := s.ownership[commitID]; ok {
		return userID, nil
	}
	return "", nil
}

// =============================================================================
// TB20: Integration Integration Test for Complete MVP Flow (TDD - RED)
// =============================================================================

// This test validates the complete user journey:
// 1. Register user
// 2. Login -> get JWT
// 3. Add repository -> get webhook URL
// 4. Simulate GitHub webhook
// 5. Generate post
// 6. Retrieve posts
// 7. Verify content

// =============================================================================
// Mock Stores for Integration Testing
// =============================================================================

// MockUserStore - in-memory user store
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

// MockRepositoryStore - in-memory repository store
type MockRepositoryStore struct {
	mu    sync.Mutex
	repos map[string]*handlers.Repository
}

func NewMockRepositoryStore() *MockRepositoryStore {
	return &MockRepositoryStore{repos: make(map[string]*handlers.Repository)}
}

func (s *MockRepositoryStore) CreateRepository(ctx context.Context, userID, githubURL, webhookSecret string) (*handlers.Repository, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.repos {
		if r.UserID == userID && r.GitHubURL == githubURL {
			return nil, handlers.ErrDuplicateRepository
		}
	}
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

func (s *MockRepositoryStore) GetRepositoryByUserAndURL(ctx context.Context, userID, githubURL string) (*handlers.Repository, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.repos {
		if r.UserID == userID && r.GitHubURL == githubURL {
			return r, nil
		}
	}
	return nil, nil
}

func (s *MockRepositoryStore) GetRepositoryByID(ctx context.Context, repoID string) (*handlers.Repository, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if repo, ok := s.repos[repoID]; ok {
		return repo, nil
	}
	return nil, nil
}

func (s *MockRepositoryStore) ListRepositoriesByUser(ctx context.Context, userID string) ([]*handlers.Repository, error) {
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

// MockPostStore - in-memory post store
type MockPostStore struct {
	mu    sync.Mutex
	posts map[string]*handlers.Post
}

func NewMockPostStore() *MockPostStore {
	return &MockPostStore{posts: make(map[string]*handlers.Post)}
}

func (s *MockPostStore) CreatePost(ctx context.Context, commitID, platform, content string) (*handlers.Post, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	post := &handlers.Post{
		ID:        uuid.New().String(),
		CommitID:  commitID,
		Platform:  platform,
		Content:   content,
		Status:    "draft",
		CreatedAt: time.Now(),
	}
	s.posts[post.ID] = post
	return post, nil
}

func (s *MockPostStore) GetPostByID(ctx context.Context, postID string) (*handlers.Post, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if post, ok := s.posts[postID]; ok {
		return post, nil
	}
	return nil, nil
}

func (s *MockPostStore) GetPostsByUserID(ctx context.Context, userID string) ([]*handlers.Post, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*handlers.Post, 0)
	for _, p := range s.posts {
		result = append(result, p)
	}
	return result, nil
}

// MockPostGenerator - mock post generator for deterministic testing
type MockPostGenerator struct {
	mu       sync.Mutex
	Response string
}

func (g *MockPostGenerator) Generate(ctx context.Context, platform string, commit *services.Commit) (*services.GeneratedPost, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	content := g.Response
	if content == "" {
		// Generate platform-appropriate content
		switch platform {
		case services.PlatformLinkedIn:
			content = "🚀 Excited to share our latest engineering achievement! " + commit.Message + " #SoftwareEngineering #Tech"
		case services.PlatformTwitter:
			content = "🚀 " + commit.Message[:min(len(commit.Message), 200)] + " #coding"
		case services.PlatformInstagram:
			content = "✨ " + commit.Message + " #coding #developer #tech #programming #devlife"
		default:
			content = commit.Message
		}
	}

	return &services.GeneratedPost{
		Platform: platform,
		Content:  content,
		CommitID: commit.ID,
	}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// =============================================================================
// Integration Test: Complete MVP Flow
// =============================================================================

func TestIntegration_CompleteMVPFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Integration integration test in short mode")
	}

	// Setup in-memory stores
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStore()
	commitStore := NewMockCommitStore(repoStore)
	postStore := NewMockPostStore()
	mockGenerator := &MockPostGenerator{}

	// Setup handlers
	authHandler := handlers.NewAuthHandler(userStore)
	secretGen := handlers.NewCryptoSecretGenerator()
	repoHandler := handlers.NewRepositoryHandler(repoStore, secretGen, "https://api.roxas.dev")
	webhookHandler := handlers.NewMultiTenantWebhookHandler(repoStore, commitStore)
	postsHandler := handlers.NewPostsHandler(postStore, commitStore, mockGenerator)

	// ==========================================================================
	// Step 1: Register user
	// ==========================================================================
	t.Log("Step 1: Register user")

	registerBody := map[string]string{
		"email":    "e2e-test@example.com",
		"password": "securepassword123",
	}
	registerJSON, _ := json.Marshal(registerBody)

	registerReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(registerJSON))
	registerReq.Header.Set("Content-Type", "application/json")

	registerRR := httptest.NewRecorder()
	authHandler.Register(registerRR, registerReq)

	if registerRR.Code != http.StatusCreated {
		t.Fatalf("Step 1 FAILED: Expected 201 Created, got %d: %s", registerRR.Code, registerRR.Body.String())
	}

	var registerResp handlers.RegisterResponse
	if err := json.NewDecoder(registerRR.Body).Decode(&registerResp); err != nil {
		t.Fatalf("Step 1 FAILED: Failed to decode register response: %v", err)
	}

	userID := registerResp.User.ID
	t.Logf("Step 1 PASSED: User registered with ID %s", userID)

	// ==========================================================================
	// Step 2: Login -> get JWT
	// ==========================================================================
	t.Log("Step 2: Login -> get JWT")

	loginBody := map[string]string{
		"email":    "e2e-test@example.com",
		"password": "securepassword123",
	}
	loginJSON, _ := json.Marshal(loginBody)

	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginJSON))
	loginReq.Header.Set("Content-Type", "application/json")

	loginRR := httptest.NewRecorder()
	authHandler.Login(loginRR, loginReq)

	if loginRR.Code != http.StatusOK {
		t.Fatalf("Step 2 FAILED: Expected 200 OK, got %d: %s", loginRR.Code, loginRR.Body.String())
	}

	var loginResp handlers.LoginResponse
	if err := json.NewDecoder(loginRR.Body).Decode(&loginResp); err != nil {
		t.Fatalf("Step 2 FAILED: Failed to decode login response: %v", err)
	}

	jwtToken := loginResp.Token
	if jwtToken == "" {
		t.Fatal("Step 2 FAILED: Expected JWT token")
	}
	t.Logf("Step 2 PASSED: Got JWT token")

	// ==========================================================================
	// Step 3: Add repository -> get webhook URL
	// ==========================================================================
	t.Log("Step 3: Add repository -> get webhook URL")

	addRepoBody := handlers.AddRepositoryRequest{
		GitHubURL: "https://github.com/e2e-test/my-repo",
	}
	addRepoJSON, _ := json.Marshal(addRepoBody)

	addRepoReq := httptest.NewRequest(http.MethodPost, "/api/v1/repositories", bytes.NewReader(addRepoJSON))
	addRepoReq.Header.Set("Content-Type", "application/json")
	addRepoReq.Header.Set("Authorization", "Bearer "+jwtToken)

	addRepoRR := httptest.NewRecorder()
	protectedRepoHandler := auth.JWTMiddleware(http.HandlerFunc(repoHandler.AddRepository))
	protectedRepoHandler.ServeHTTP(addRepoRR, addRepoReq)

	if addRepoRR.Code != http.StatusCreated {
		t.Fatalf("Step 3 FAILED: Expected 201 Created, got %d: %s", addRepoRR.Code, addRepoRR.Body.String())
	}

	var addRepoResp handlers.AddRepositoryResponse
	if err := json.NewDecoder(addRepoRR.Body).Decode(&addRepoResp); err != nil {
		t.Fatalf("Step 3 FAILED: Failed to decode add repo response: %v", err)
	}

	repoID := addRepoResp.Repository.ID
	webhookSecret := addRepoResp.Webhook.Secret
	t.Logf("Step 3 PASSED: Repository added with ID %s, webhook secret obtained", repoID)

	// ==========================================================================
	// Step 4: Simulate GitHub webhook
	// ==========================================================================
	t.Log("Step 4: Simulate GitHub webhook")

	webhookPayload := map[string]interface{}{
		"ref": "refs/heads/main",
		"repository": map[string]interface{}{
			"html_url":  "https://github.com/e2e-test/my-repo",
			"full_name": "e2e-test/my-repo",
		},
		"commits": []map[string]interface{}{
			{
				"id":        "abc123def456789012345678901234567890abcd",
				"message":   "feat: implement amazing new feature for users",
				"url":       "https://github.com/e2e-test/my-repo/commit/abc123",
				"timestamp": time.Now().Format(time.RFC3339),
				"author": map[string]interface{}{
					"name":  "Integration Test Author",
					"email": "e2e@example.com",
				},
			},
		},
	}
	webhookJSON, _ := json.Marshal(webhookPayload)

	// Generate GitHub signature
	signature := "sha256=" + generateHMAC(webhookJSON, webhookSecret)

	webhookReq := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+repoID, bytes.NewReader(webhookJSON))
	webhookReq.Header.Set("Content-Type", "application/json")
	webhookReq.Header.Set("X-Hub-Signature-256", signature)
	webhookReq.Header.Set("X-GitHub-Event", "push")

	webhookRR := httptest.NewRecorder()
	webhookHandler.ServeHTTP(webhookRR, webhookReq)

	if webhookRR.Code != http.StatusOK {
		t.Fatalf("Step 4 FAILED: Expected 200 OK, got %d: %s", webhookRR.Code, webhookRR.Body.String())
	}

	t.Log("Step 4 PASSED: Webhook accepted")

	// Verify commit was stored
	storedCommit, _ := commitStore.GetCommitBySHA(context.Background(), repoID, "abc123def456789012345678901234567890abcd")
	if storedCommit == nil {
		t.Fatal("Step 4 FAILED: Commit not stored after webhook")
	}
	commitID := storedCommit.ID
	t.Logf("Step 4 VERIFIED: Commit stored with ID %s", commitID)

	// ==========================================================================
	// Step 5: Generate post
	// ==========================================================================
	t.Log("Step 5: Generate post for LinkedIn")

	createPostReq := httptest.NewRequest(http.MethodPost, "/api/v1/commits/"+commitID+"/posts?platform=linkedin", nil)
	createPostReq.Header.Set("Authorization", "Bearer "+jwtToken)

	createPostRR := httptest.NewRecorder()
	protectedPostsHandler := auth.JWTMiddleware(http.HandlerFunc(postsHandler.CreatePost))
	protectedPostsHandler.ServeHTTP(createPostRR, createPostReq)

	if createPostRR.Code != http.StatusCreated {
		t.Fatalf("Step 5 FAILED: Expected 201 Created, got %d: %s", createPostRR.Code, createPostRR.Body.String())
	}

	var createPostResp handlers.CreatePostResponse
	if err := json.NewDecoder(createPostRR.Body).Decode(&createPostResp); err != nil {
		t.Fatalf("Step 5 FAILED: Failed to decode create post response: %v", err)
	}

	postID := createPostResp.Post.ID
	if createPostResp.Post.Platform != "linkedin" {
		t.Errorf("Step 5 FAILED: Expected platform linkedin, got %s", createPostResp.Post.Platform)
	}
	if createPostResp.Post.Status != "draft" {
		t.Errorf("Step 5 FAILED: Expected status draft, got %s", createPostResp.Post.Status)
	}
	t.Logf("Step 5 PASSED: Post generated with ID %s, status %s", postID, createPostResp.Post.Status)

	// ==========================================================================
	// Step 6: Retrieve posts
	// ==========================================================================
	t.Log("Step 6: Retrieve posts")

	listPostsReq := httptest.NewRequest(http.MethodGet, "/api/v1/posts", nil)
	listPostsReq.Header.Set("Authorization", "Bearer "+jwtToken)

	listPostsRR := httptest.NewRecorder()
	protectedListHandler := auth.JWTMiddleware(http.HandlerFunc(postsHandler.ListPosts))
	protectedListHandler.ServeHTTP(listPostsRR, listPostsReq)

	if listPostsRR.Code != http.StatusOK {
		t.Fatalf("Step 6 FAILED: Expected 200 OK, got %d: %s", listPostsRR.Code, listPostsRR.Body.String())
	}

	var listPostsResp handlers.ListPostsResponse
	if err := json.NewDecoder(listPostsRR.Body).Decode(&listPostsResp); err != nil {
		t.Fatalf("Step 6 FAILED: Failed to decode list posts response: %v", err)
	}

	if len(listPostsResp.Posts) == 0 {
		t.Fatal("Step 6 FAILED: Expected at least 1 post")
	}
	t.Logf("Step 6 PASSED: Retrieved %d posts", len(listPostsResp.Posts))

	// ==========================================================================
	// Step 7: Verify content
	// ==========================================================================
	t.Log("Step 7: Verify content")

	getPostReq := httptest.NewRequest(http.MethodGet, "/api/v1/posts/"+postID, nil)
	getPostReq.Header.Set("Authorization", "Bearer "+jwtToken)

	getPostRR := httptest.NewRecorder()
	protectedGetHandler := auth.JWTMiddleware(http.HandlerFunc(postsHandler.GetPost))
	protectedGetHandler.ServeHTTP(getPostRR, getPostReq)

	if getPostRR.Code != http.StatusOK {
		t.Fatalf("Step 7 FAILED: Expected 200 OK, got %d: %s", getPostRR.Code, getPostRR.Body.String())
	}

	var getPostResp handlers.GetPostResponse
	if err := json.NewDecoder(getPostRR.Body).Decode(&getPostResp); err != nil {
		t.Fatalf("Step 7 FAILED: Failed to decode get post response: %v", err)
	}

	// Verify post content contains expected elements
	content := getPostResp.Post.Content
	if content == "" {
		t.Fatal("Step 7 FAILED: Post content is empty")
	}

	// Should reference the commit message or feature
	if !strings.Contains(strings.ToLower(content), "feature") &&
		!strings.Contains(strings.ToLower(content), "amazing") &&
		!strings.Contains(strings.ToLower(content), "users") {
		t.Errorf("Step 7 FAILED: Post content should reference commit message, got: %s", content)
	}

	t.Logf("Step 7 PASSED: Post content verified: %s", content[:min(len(content), 50)]+"...")

	t.Log("=== Integration MVP Flow Test COMPLETED SUCCESSFULLY ===")
}

// =============================================================================
// Integration Test: Multi-Tenant Isolation
// =============================================================================

func TestIntegration_MultiTenantIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Integration integration test in short mode")
	}

	// Setup stores
	userStore := NewMockUserStore()
	repoStore := NewMockRepositoryStore()
	commitStore := NewMockCommitStore(repoStore)
	postStore := NewMockPostStore()
	mockGenerator := &MockPostGenerator{}

	// Setup handlers
	authHandler := handlers.NewAuthHandler(userStore)
	secretGen := handlers.NewCryptoSecretGenerator()
	repoHandler := handlers.NewRepositoryHandler(repoStore, secretGen, "https://api.roxas.dev")
	webhookHandler := handlers.NewMultiTenantWebhookHandler(repoStore, commitStore)
	postsHandler := handlers.NewPostsHandler(postStore, commitStore, mockGenerator)

	// Create User 1
	user1Token := createTestUser(t, authHandler, "user1@example.com", "password123")
	repo1ID, webhook1Secret := createTestRepo(t, repoHandler, user1Token, "https://github.com/user1/repo")

	// Create User 2
	user2Token := createTestUser(t, authHandler, "user2@example.com", "password456")
	_, _ = createTestRepo(t, repoHandler, user2Token, "https://github.com/user2/repo")

	// User 1 receives webhook and creates commit
	sendTestWebhook(t, webhookHandler, repo1ID, webhook1Secret, "user1-commit-sha", "feat: user1 feature")

	// Get user1's commit
	commit, _ := commitStore.GetCommitBySHA(context.Background(), repo1ID, "user1-commit-sha")
	if commit == nil {
		t.Fatal("User1 commit not stored")
	}

	// User 1 generates post
	createTestPost(t, postsHandler, user1Token, commit.ID, "linkedin")

	// User 2 tries to access User 1's commit (should fail with 403)
	createPostReq := httptest.NewRequest(http.MethodPost, "/api/v1/commits/"+commit.ID+"/posts?platform=twitter", nil)
	createPostReq.Header.Set("Authorization", "Bearer "+user2Token)

	createPostRR := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(postsHandler.CreatePost))
	protectedHandler.ServeHTTP(createPostRR, createPostReq)

	if createPostRR.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden when user2 accesses user1's commit, got %d: %s",
			createPostRR.Code, createPostRR.Body.String())
	}

	t.Log("Multi-tenant isolation verified: User 2 cannot access User 1's commits")
}

// =============================================================================
// Integration Helper Functions
// =============================================================================

func createTestUser(t *testing.T, authHandler *handlers.AuthHandler, email, password string) string {
	t.Helper()

	// Register
	registerBody, _ := json.Marshal(map[string]string{"email": email, "password": password})
	registerReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(registerBody))
	registerReq.Header.Set("Content-Type", "application/json")
	registerRR := httptest.NewRecorder()
	authHandler.Register(registerRR, registerReq)

	if registerRR.Code != http.StatusCreated {
		t.Fatalf("Failed to register user %s: %d: %s", email, registerRR.Code, registerRR.Body.String())
	}

	// Login
	loginBody, _ := json.Marshal(map[string]string{"email": email, "password": password})
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRR := httptest.NewRecorder()
	authHandler.Login(loginRR, loginReq)

	var loginResp handlers.LoginResponse
	json.NewDecoder(loginRR.Body).Decode(&loginResp)
	return loginResp.Token
}

func createTestRepo(t *testing.T, repoHandler *handlers.RepositoryHandler, token, githubURL string) (string, string) {
	t.Helper()

	body, _ := json.Marshal(handlers.AddRepositoryRequest{GitHubURL: githubURL})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/repositories", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	protected := auth.JWTMiddleware(http.HandlerFunc(repoHandler.AddRepository))
	protected.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Failed to create repo: %d: %s", rr.Code, rr.Body.String())
	}

	var resp handlers.AddRepositoryResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	return resp.Repository.ID, resp.Webhook.Secret
}

func sendTestWebhook(t *testing.T, handler *handlers.MultiTenantWebhookHandler, repoID, secret, sha, message string) {
	t.Helper()

	payload := map[string]interface{}{
		"ref":        "refs/heads/main",
		"repository": map[string]interface{}{"html_url": "https://github.com/test/repo", "full_name": "test/repo"},
		"commits": []map[string]interface{}{
			{
				"id":        sha,
				"message":   message,
				"url":       "https://github.com/test/repo/commit/" + sha,
				"timestamp": time.Now().Format(time.RFC3339),
				"author":    map[string]interface{}{"name": "Test", "email": "test@example.com"},
			},
		},
	}
	body, _ := json.Marshal(payload)
	signature := "sha256=" + generateHMAC(body, secret)

	req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+repoID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature-256", signature)
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Webhook failed: %d: %s", rr.Code, rr.Body.String())
	}
}

func createTestPost(t *testing.T, handler *handlers.PostsHandler, token, commitID, platform string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/commits/"+commitID+"/posts?platform="+platform, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	protected := auth.JWTMiddleware(http.HandlerFunc(handler.CreatePost))
	protected.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Failed to create post: %d: %s", rr.Code, rr.Body.String())
	}
}
