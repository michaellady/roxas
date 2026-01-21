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
	"github.com/mikelady/roxas/internal/clients"
	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// alice-91: Post to Threads Handler Tests (TDD - RED)
// Tests for POST /drafts/{id}/post endpoint
// =============================================================================

// =============================================================================
// Mock Types for Post to Threads Tests
// =============================================================================

// Draft represents a draft post in the database
type Draft struct {
	ID               string
	UserID           string
	RepositoryID     string
	Ref              string
	BeforeSHA        string
	AfterSHA         string
	CommitSHAs       []string
	GeneratedContent string
	EditedContent    string
	Status           string // draft, posted, failed, error
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// MockDraftStore is an in-memory draft store for testing
type MockDraftStore struct {
	mu     sync.RWMutex
	drafts map[string]*Draft
}

func NewMockDraftStore() *MockDraftStore {
	return &MockDraftStore{
		drafts: make(map[string]*Draft),
	}
}

func (m *MockDraftStore) CreateDraft(ctx context.Context, draft *Draft) (*Draft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if draft.ID == "" {
		draft.ID = uuid.New().String()
	}
	draft.CreatedAt = time.Now()
	draft.UpdatedAt = time.Now()
	if draft.Status == "" {
		draft.Status = "draft"
	}
	m.drafts[draft.ID] = draft
	return draft, nil
}

func (m *MockDraftStore) GetDraft(ctx context.Context, draftID string) (*Draft, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if draft, ok := m.drafts[draftID]; ok {
		return draft, nil
	}
	return nil, nil
}

func (m *MockDraftStore) GetDraftByUserID(ctx context.Context, draftID, userID string) (*Draft, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if draft, ok := m.drafts[draftID]; ok {
		if draft.UserID == userID {
			return draft, nil
		}
		return nil, nil // Not owned by this user
	}
	return nil, nil
}

func (m *MockDraftStore) UpdateDraftStatus(ctx context.Context, draftID, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if draft, ok := m.drafts[draftID]; ok {
		draft.Status = status
		draft.UpdatedAt = time.Now()
		return nil
	}
	return errors.New("draft not found")
}

func (m *MockDraftStore) ListDraftsByUser(ctx context.Context, userID string) ([]*Draft, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Draft
	for _, d := range m.drafts {
		if d.UserID == userID {
			result = append(result, d)
		}
	}
	return result, nil
}

// MockPostStoreForThreads extends post store for draft-based posts
type MockPostStoreForThreads struct {
	mu    sync.RWMutex
	posts map[string]*PostFromDraft
}

// PostFromDraft represents a post created from a draft
type PostFromDraft struct {
	ID              string
	DraftID         string
	UserID          string
	Platform        string
	Content         string
	Status          string
	PlatformPostID  string
	PlatformPostURL string
	ErrorMessage    string
	CreatedAt       time.Time
	PostedAt        *time.Time
}

func NewMockPostStoreForThreads() *MockPostStoreForThreads {
	return &MockPostStoreForThreads{
		posts: make(map[string]*PostFromDraft),
	}
}

func (m *MockPostStoreForThreads) CreatePostFromDraft(ctx context.Context, draftID, userID, platform, content string) (*PostFromDraft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	post := &PostFromDraft{
		ID:        uuid.New().String(),
		DraftID:   draftID,
		UserID:    userID,
		Platform:  platform,
		Content:   content,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	m.posts[post.ID] = post
	return post, nil
}

func (m *MockPostStoreForThreads) UpdatePostResult(ctx context.Context, postID string, platformPostID, platformPostURL string, postedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if post, ok := m.posts[postID]; ok {
		post.PlatformPostID = platformPostID
		post.PlatformPostURL = platformPostURL
		post.PostedAt = &postedAt
		post.Status = "posted"
		return nil
	}
	return errors.New("post not found")
}

func (m *MockPostStoreForThreads) UpdatePostError(ctx context.Context, postID, errorMessage string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if post, ok := m.posts[postID]; ok {
		post.ErrorMessage = errorMessage
		post.Status = "failed"
		return nil
	}
	return errors.New("post not found")
}

func (m *MockPostStoreForThreads) GetPostByID(ctx context.Context, postID string) (*PostFromDraft, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if post, ok := m.posts[postID]; ok {
		return post, nil
	}
	return nil, nil
}

// MockThreadsClient is a mock implementation of SocialClient for Threads
type MockThreadsClient struct {
	PostResult *services.PostResult
	PostError  error
	PostCalls  []services.PostContent
}

func NewMockThreadsClient() *MockThreadsClient {
	return &MockThreadsClient{
		PostCalls: make([]services.PostContent, 0),
	}
}

func (m *MockThreadsClient) Post(ctx context.Context, content services.PostContent) (*services.PostResult, error) {
	m.PostCalls = append(m.PostCalls, content)
	if m.PostError != nil {
		return nil, m.PostError
	}
	if m.PostResult != nil {
		return m.PostResult, nil
	}
	return &services.PostResult{
		PostID:  "threads-post-" + uuid.New().String(),
		PostURL: "https://www.threads.net/@testuser/post/abc123",
	}, nil
}

func (m *MockThreadsClient) ValidateContent(content services.PostContent) error {
	if len(content.Text) > 500 {
		return errors.New("text exceeds 500 character limit")
	}
	if len(content.Text) == 0 && len(content.Media) == 0 {
		return errors.New("thread must have text or media")
	}
	return nil
}

func (m *MockThreadsClient) Platform() string {
	return services.PlatformThreads
}

func (m *MockThreadsClient) GetRateLimits() services.RateLimitInfo {
	return services.RateLimitInfo{
		Limit:     250,
		Remaining: 245,
		ResetAt:   time.Now().Add(24 * time.Hour),
	}
}

// MockCredentialStoreForThreads provides credential lookups for testing
type MockCredentialStoreForThreads struct {
	mu          sync.RWMutex
	credentials map[string]map[string]*services.PlatformCredentials
}

func NewMockCredentialStoreForThreads() *MockCredentialStoreForThreads {
	return &MockCredentialStoreForThreads{
		credentials: make(map[string]map[string]*services.PlatformCredentials),
	}
}

func (m *MockCredentialStoreForThreads) AddCredentials(cred *services.PlatformCredentials) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.credentials[cred.UserID] == nil {
		m.credentials[cred.UserID] = make(map[string]*services.PlatformCredentials)
	}
	m.credentials[cred.UserID][cred.Platform] = cred
}

func (m *MockCredentialStoreForThreads) GetCredentials(ctx context.Context, userID, platform string) (*services.PlatformCredentials, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if userCreds, ok := m.credentials[userID]; ok {
		if cred, ok := userCreds[platform]; ok {
			return cred, nil
		}
	}
	return nil, nil
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func createAuthenticatedRequestForThreads(t *testing.T, method, path string, body []byte, userID, email string) *http.Request {
	t.Helper()

	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, nil)
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
// POST /drafts/{id}/post Tests - Success Cases
// =============================================================================

// TestPostDraftToThreads_Success tests successful posting of a draft to Threads
func TestPostDraftToThreads_Success(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	email := "test@example.com"

	// Create a draft
	draft, _ := draftStore.CreateDraft(context.Background(), &Draft{
		UserID:           userID,
		RepositoryID:     "repo-456",
		GeneratedContent: "Check out this awesome commit! 🚀 #coding",
		EditedContent:    "Check out this awesome commit! 🚀 #coding",
		Status:           "draft",
	})

	// Add Threads credentials for the user
	expiresAt := time.Now().Add(24 * time.Hour)
	credStore.AddCredentials(&services.PlatformCredentials{
		UserID:         userID,
		Platform:       services.PlatformThreads,
		AccessToken:    "valid-threads-token",
		TokenExpiresAt: &expiresAt,
	})

	// Set expected post result
	threadsClient.PostResult = &services.PostResult{
		PostID:  "threads-post-123",
		PostURL: "https://www.threads.net/@testuser/post/abc123",
	}

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post?platform=threads", nil, userID, email)

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp PostDraftResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify post was created
	if resp.Post.ID == "" {
		t.Error("Expected post ID to be set")
	}
	if resp.Post.Platform != services.PlatformThreads {
		t.Errorf("Expected platform threads, got %s", resp.Post.Platform)
	}
	if resp.Post.PlatformPostID != "threads-post-123" {
		t.Errorf("Expected platform post ID 'threads-post-123', got %s", resp.Post.PlatformPostID)
	}
	if resp.Post.PlatformPostURL != "https://www.threads.net/@testuser/post/abc123" {
		t.Errorf("Expected post URL, got %s", resp.Post.PlatformPostURL)
	}

	// Verify Threads API was called
	if len(threadsClient.PostCalls) != 1 {
		t.Fatalf("Expected 1 Threads API call, got %d", len(threadsClient.PostCalls))
	}
	if threadsClient.PostCalls[0].Text != draft.EditedContent {
		t.Errorf("Expected content '%s', got '%s'", draft.EditedContent, threadsClient.PostCalls[0].Text)
	}

	// Verify draft status was updated to 'posted'
	updatedDraft, _ := draftStore.GetDraft(context.Background(), draft.ID)
	if updatedDraft.Status != "posted" {
		t.Errorf("Expected draft status 'posted', got '%s'", updatedDraft.Status)
	}
}

// TestPostDraftToThreads_UsesEditedContent tests that edited content is posted, not generated
func TestPostDraftToThreads_UsesEditedContent(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"

	// Create a draft with different generated vs edited content
	draft, _ := draftStore.CreateDraft(context.Background(), &Draft{
		UserID:           userID,
		RepositoryID:     "repo-456",
		GeneratedContent: "Original AI generated content",
		EditedContent:    "User edited content that should be posted",
		Status:           "draft",
	})

	expiresAt := time.Now().Add(24 * time.Hour)
	credStore.AddCredentials(&services.PlatformCredentials{
		UserID:         userID,
		Platform:       services.PlatformThreads,
		AccessToken:    "valid-token",
		TokenExpiresAt: &expiresAt,
	})

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post?platform=threads", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify edited content was posted, not generated
	if len(threadsClient.PostCalls) != 1 {
		t.Fatalf("Expected 1 API call, got %d", len(threadsClient.PostCalls))
	}
	if threadsClient.PostCalls[0].Text != "User edited content that should be posted" {
		t.Errorf("Expected edited content, got '%s'", threadsClient.PostCalls[0].Text)
	}
}

// =============================================================================
// POST /drafts/{id}/post Tests - Error Cases
// =============================================================================

// TestPostDraftToThreads_DraftNotFound tests 404 for non-existent draft
func TestPostDraftToThreads_DraftNotFound(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/nonexistent-draft/post?platform=threads", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 Not Found, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestPostDraftToThreads_DraftBelongsToOtherUser tests 403 for accessing another user's draft
func TestPostDraftToThreads_DraftBelongsToOtherUser(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	// Draft belongs to owner
	ownerID := "user-owner"
	draft, _ := draftStore.CreateDraft(context.Background(), &Draft{
		UserID:           ownerID,
		RepositoryID:     "repo-456",
		GeneratedContent: "Owner's draft",
		EditedContent:    "Owner's draft",
		Status:           "draft",
	})

	// Attacker tries to post it
	attackerID := "user-attacker"
	attackerExpiry := time.Now().Add(24 * time.Hour)
	credStore.AddCredentials(&services.PlatformCredentials{
		UserID:         attackerID,
		Platform:       services.PlatformThreads,
		AccessToken:    "attacker-token",
		TokenExpiresAt: &attackerExpiry,
	})

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post?platform=threads", nil, attackerID, "attacker@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 Forbidden, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestPostDraftToThreads_NoAuth tests 401 when not authenticated
func TestPostDraftToThreads_NoAuth(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := httptest.NewRequest(http.MethodPost, "/drafts/some-draft-id/post?platform=threads", nil)

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestPostDraftToThreads_MissingPlatform tests 400 when platform query param is missing
func TestPostDraftToThreads_MissingPlatform(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), &Draft{
		UserID:           userID,
		RepositoryID:     "repo-456",
		GeneratedContent: "Test content",
		EditedContent:    "Test content",
		Status:           "draft",
	})

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	// No platform query parameter
	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 Bad Request, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestPostDraftToThreads_InvalidPlatform tests 400 for unsupported platform
func TestPostDraftToThreads_InvalidPlatform(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), &Draft{
		UserID:           userID,
		RepositoryID:     "repo-456",
		GeneratedContent: "Test content",
		EditedContent:    "Test content",
		Status:           "draft",
	})

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post?platform=myspace", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 Bad Request, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestPostDraftToThreads_NoCredentials tests 400 when user has no Threads connection
func TestPostDraftToThreads_NoCredentials(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads() // Empty - no credentials

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), &Draft{
		UserID:           userID,
		RepositoryID:     "repo-456",
		GeneratedContent: "Test content",
		EditedContent:    "Test content",
		Status:           "draft",
	})

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post?platform=threads", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 Bad Request for missing credentials, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ErrorResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Error == "" {
		t.Error("Expected error message about missing connection")
	}
}

// TestPostDraftToThreads_AlreadyPosted tests 400 when draft is already posted
func TestPostDraftToThreads_AlreadyPosted(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), &Draft{
		UserID:           userID,
		RepositoryID:     "repo-456",
		GeneratedContent: "Test content",
		EditedContent:    "Test content",
		Status:           "posted", // Already posted!
	})

	expiresAt := time.Now().Add(24 * time.Hour)
	credStore.AddCredentials(&services.PlatformCredentials{
		UserID:         userID,
		Platform:       services.PlatformThreads,
		AccessToken:    "valid-token",
		TokenExpiresAt: &expiresAt,
	})

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post?platform=threads", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 Bad Request for already posted draft, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// POST /drafts/{id}/post Tests - Threads API Error Handling
// =============================================================================

// TestPostDraftToThreads_ExpiredToken tests handling of expired Threads token
func TestPostDraftToThreads_ExpiredToken(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), &Draft{
		UserID:           userID,
		RepositoryID:     "repo-456",
		GeneratedContent: "Test content",
		EditedContent:    "Test content",
		Status:           "draft",
	})

	expiredAt := time.Now().Add(-24 * time.Hour) // Expired!
	credStore.AddCredentials(&services.PlatformCredentials{
		UserID:         userID,
		Platform:       services.PlatformThreads,
		AccessToken:    "expired-token",
		TokenExpiresAt: &expiredAt,
	})

	// Simulate Threads API returning authentication error
	threadsClient.PostError = clients.ErrThreadsAuthentication

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post?platform=threads", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	// Should return 401 or 400 indicating token needs refresh
	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 401 or 400 for expired token, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ErrorResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Error == "" {
		t.Error("Expected error message about expired token")
	}

	// Verify draft status was updated to 'failed' or 'error'
	updatedDraft, _ := draftStore.GetDraft(context.Background(), draft.ID)
	if updatedDraft.Status != "failed" && updatedDraft.Status != "error" {
		t.Errorf("Expected draft status 'failed' or 'error', got '%s'", updatedDraft.Status)
	}
}

// TestPostDraftToThreads_RateLimited tests handling of Threads rate limiting
func TestPostDraftToThreads_RateLimited(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), &Draft{
		UserID:           userID,
		RepositoryID:     "repo-456",
		GeneratedContent: "Test content",
		EditedContent:    "Test content",
		Status:           "draft",
	})

	validExpiresAt := time.Now().Add(24 * time.Hour)
	credStore.AddCredentials(&services.PlatformCredentials{
		UserID:         userID,
		Platform:       services.PlatformThreads,
		AccessToken:    "valid-token",
		TokenExpiresAt: &validExpiresAt,
	})

	// Simulate Threads API returning rate limit error
	threadsClient.PostError = clients.ErrThreadsRateLimited

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post?platform=threads", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	// Should return 429 Too Many Requests
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429 Too Many Requests, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ErrorResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Error == "" {
		t.Error("Expected error message about rate limiting")
	}

	// Draft should remain in 'draft' status (can retry later)
	updatedDraft, _ := draftStore.GetDraft(context.Background(), draft.ID)
	if updatedDraft.Status != "draft" {
		t.Errorf("Expected draft status to remain 'draft' for rate limit, got '%s'", updatedDraft.Status)
	}
}

// TestPostDraftToThreads_ThreadsAPIError tests handling of generic Threads API errors
func TestPostDraftToThreads_ThreadsAPIError(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), &Draft{
		UserID:           userID,
		RepositoryID:     "repo-456",
		GeneratedContent: "Test content",
		EditedContent:    "Test content",
		Status:           "draft",
	})

	validExpiresAt := time.Now().Add(24 * time.Hour)
	credStore.AddCredentials(&services.PlatformCredentials{
		UserID:         userID,
		Platform:       services.PlatformThreads,
		AccessToken:    "valid-token",
		TokenExpiresAt: &validExpiresAt,
	})

	// Simulate generic Threads API error
	threadsClient.PostError = clients.ErrThreadsPostFailed

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post?platform=threads", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	// Should return 502 Bad Gateway or 500 Internal Server Error
	if rr.Code != http.StatusBadGateway && rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 502 or 500, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify draft status was updated to 'failed'
	updatedDraft, _ := draftStore.GetDraft(context.Background(), draft.ID)
	if updatedDraft.Status != "failed" {
		t.Errorf("Expected draft status 'failed', got '%s'", updatedDraft.Status)
	}
}

// TestPostDraftToThreads_ContentTooLong tests validation of content length
func TestPostDraftToThreads_ContentTooLong(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"

	// Create content that exceeds Threads 500 char limit
	longContent := make([]byte, 600)
	for i := range longContent {
		longContent[i] = 'a'
	}

	draft, _ := draftStore.CreateDraft(context.Background(), &Draft{
		UserID:           userID,
		RepositoryID:     "repo-456",
		GeneratedContent: string(longContent),
		EditedContent:    string(longContent),
		Status:           "draft",
	})

	validExpiresAt := time.Now().Add(24 * time.Hour)
	credStore.AddCredentials(&services.PlatformCredentials{
		UserID:         userID,
		Platform:       services.PlatformThreads,
		AccessToken:    "valid-token",
		TokenExpiresAt: &validExpiresAt,
	})

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post?platform=threads", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 Bad Request for content too long, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ErrorResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Error == "" {
		t.Error("Expected error message about content length")
	}
}

// =============================================================================
// POST /drafts/{id}/post Tests - Post Record Creation
// =============================================================================

// TestPostDraftToThreads_CreatesPostRecord tests that a post record is created in the database
func TestPostDraftToThreads_CreatesPostRecord(t *testing.T) {
	t.Skip("PostDraftHandler not implemented yet - TDD RED phase")

	draftStore := NewMockDraftStore()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), &Draft{
		UserID:           userID,
		RepositoryID:     "repo-456",
		GeneratedContent: "Test content",
		EditedContent:    "Test content",
		Status:           "draft",
	})

	validExpiresAt := time.Now().Add(24 * time.Hour)
	credStore.AddCredentials(&services.PlatformCredentials{
		UserID:         userID,
		Platform:       services.PlatformThreads,
		AccessToken:    "valid-token",
		TokenExpiresAt: &validExpiresAt,
	})

	threadsClient.PostResult = &services.PostResult{
		PostID:  "threads-post-xyz",
		PostURL: "https://www.threads.net/@testuser/post/xyz",
	}

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post?platform=threads", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp PostDraftResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	// Verify post record was created with correct data
	post, err := postStore.GetPostByID(context.Background(), resp.Post.ID)
	if err != nil {
		t.Fatalf("Failed to get post: %v", err)
	}
	if post == nil {
		t.Fatal("Expected post record to be created")
	}
	if post.DraftID != draft.ID {
		t.Errorf("Expected draft ID '%s', got '%s'", draft.ID, post.DraftID)
	}
	if post.Platform != services.PlatformThreads {
		t.Errorf("Expected platform 'threads', got '%s'", post.Platform)
	}
	if post.PlatformPostID != "threads-post-xyz" {
		t.Errorf("Expected platform post ID 'threads-post-xyz', got '%s'", post.PlatformPostID)
	}
	if post.PlatformPostURL != "https://www.threads.net/@testuser/post/xyz" {
		t.Errorf("Expected post URL, got '%s'", post.PlatformPostURL)
	}
	if post.Status != "posted" {
		t.Errorf("Expected status 'posted', got '%s'", post.Status)
	}
	if post.PostedAt == nil {
		t.Error("Expected posted_at to be set")
	}
}

// =============================================================================
// Response Types (placeholder - will be defined in handler)
// =============================================================================

// PostDraftResponse is the response for posting a draft
type PostDraftResponse struct {
	Post PostFromDraftResponse `json:"post"`
}

// PostFromDraftResponse is the post object in API responses
type PostFromDraftResponse struct {
	ID              string  `json:"id"`
	DraftID         string  `json:"draft_id"`
	Platform        string  `json:"platform"`
	Content         string  `json:"content"`
	Status          string  `json:"status"`
	PlatformPostID  string  `json:"platform_post_id"`
	PlatformPostURL string  `json:"platform_post_url"`
	ErrorMessage    string  `json:"error_message,omitempty"`
	PostedAt        *string `json:"posted_at,omitempty"`
}

// Note: PostDraftHandler and NewPostDraftHandler are defined in the implementation file.
// These tests are written to fail initially (TDD RED phase) until the handler is implemented.
