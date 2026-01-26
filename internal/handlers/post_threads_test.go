package handlers

import (
	"bytes"
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
// alice-91: Post to Threads Handler Tests
// Tests for POST /drafts/{id}/post endpoint
// =============================================================================

// =============================================================================
// Mock Types for Post to Threads Tests
// These mocks implement the interfaces defined in post_draft.go
// =============================================================================

// MockDraftStoreForPost is an in-memory draft store implementing DraftStoreForPost
type MockDraftStoreForPost struct {
	mu     sync.RWMutex
	drafts map[string]*Draft
}

func NewMockDraftStoreForPost() *MockDraftStoreForPost {
	return &MockDraftStoreForPost{
		drafts: make(map[string]*Draft),
	}
}

func (m *MockDraftStoreForPost) CreateDraft(ctx context.Context, userID, repoID string, genContent, editContent string) (*Draft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := uuid.New().String()
	draft := &Draft{
		ID:               id,
		UserID:           userID,
		RepositoryID:     repoID,
		GeneratedContent: strPtr(genContent),
		EditedContent:    strPtr(editContent),
		Status:           "draft",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	m.drafts[id] = draft
	return draft, nil
}

func (m *MockDraftStoreForPost) GetDraft(ctx context.Context, draftID string) (*Draft, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if draft, ok := m.drafts[draftID]; ok {
		return draft, nil
	}
	return nil, nil
}

func (m *MockDraftStoreForPost) GetDraftByUserID(ctx context.Context, draftID, userID string) (*Draft, error) {
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

func (m *MockDraftStoreForPost) UpdateDraftStatus(ctx context.Context, draftID, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if draft, ok := m.drafts[draftID]; ok {
		draft.Status = status
		draft.UpdatedAt = time.Now()
		return nil
	}
	return errors.New("draft not found")
}

// strPtr is a helper to create string pointers
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// MockPostStoreForThreads implements PostStoreForDraft
type MockPostStoreForThreads struct {
	mu    sync.RWMutex
	posts map[string]*PostFromDraft
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
// POST /drafts/{id}/post Tests - Success Cases
// =============================================================================

// TestPostDraftToThreads_Success tests successful posting of a draft to Threads
func TestPostDraftToThreads_Success(t *testing.T) {
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	email := "test@example.com"

	// Create a draft
	draft, _ := draftStore.CreateDraft(context.Background(), userID, "repo-456",
		"Check out this awesome commit! 🚀 #coding",
		"Check out this awesome commit! 🚀 #coding")

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
	if threadsClient.PostCalls[0].Text != "Check out this awesome commit! 🚀 #coding" {
		t.Errorf("Expected content '%s', got '%s'", "Check out this awesome commit! 🚀 #coding", threadsClient.PostCalls[0].Text)
	}

	// Verify draft status was updated to 'posted'
	updatedDraft, _ := draftStore.GetDraft(context.Background(), draft.ID)
	if updatedDraft.Status != "posted" {
		t.Errorf("Expected draft status 'posted', got '%s'", updatedDraft.Status)
	}
}

// TestPostDraftToThreads_UsesEditedContent tests that edited content is posted, not generated
func TestPostDraftToThreads_UsesEditedContent(t *testing.T) {
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"

	// Create a draft with different generated vs edited content
	draft, _ := draftStore.CreateDraft(context.Background(), userID, "repo-456",
		"Original AI generated content",
		"User edited content that should be posted")

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
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
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
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	// Draft belongs to owner
	ownerID := "user-owner"
	draft, _ := draftStore.CreateDraft(context.Background(), ownerID, "repo-456",
		"Owner's draft", "Owner's draft")

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
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
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
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), userID, "repo-456",
		"Test content", "Test content")

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
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), userID, "repo-456",
		"Test content", "Test content")

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
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads() // Empty - no credentials

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), userID, "repo-456",
		"Test content", "Test content")

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
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), userID, "repo-456",
		"Test content", "Test content")
	// Mark as already posted
	draftStore.UpdateDraftStatus(context.Background(), draft.ID, "posted")

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
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), userID, "repo-456",
		"Test content", "Test content")

	expiredAt := time.Now().Add(-24 * time.Hour) // Expired!
	credStore.AddCredentials(&services.PlatformCredentials{
		UserID:         userID,
		Platform:       services.PlatformThreads,
		AccessToken:    "expired-token",
		TokenExpiresAt: &expiredAt,
	})

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post?platform=threads", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	// Should return 400 indicating token needs refresh (caught before API call)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for expired token, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestPostDraftToThreads_AuthErrorFromAPI tests handling when Threads API returns auth error
func TestPostDraftToThreads_AuthErrorFromAPI(t *testing.T) {
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), userID, "repo-456",
		"Test content", "Test content")

	validExpiresAt := time.Now().Add(24 * time.Hour)
	credStore.AddCredentials(&services.PlatformCredentials{
		UserID:         userID,
		Platform:       services.PlatformThreads,
		AccessToken:    "revoked-token",
		TokenExpiresAt: &validExpiresAt,
	})

	// Simulate Threads API returning authentication error
	threadsClient.PostError = clients.ErrThreadsAuthentication

	handler := NewPostDraftHandler(draftStore, postStore, threadsClient, credStore)

	req := createAuthenticatedRequestForThreads(t, http.MethodPost,
		"/drafts/"+draft.ID+"/post?platform=threads", nil, userID, "test@example.com")

	rr := httptest.NewRecorder()
	protectedHandler := auth.JWTMiddleware(http.HandlerFunc(handler.PostDraft))
	protectedHandler.ServeHTTP(rr, req)

	// Should return 401 indicating authentication failed
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for auth error from API, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify draft status was updated to 'failed'
	updatedDraft, _ := draftStore.GetDraft(context.Background(), draft.ID)
	if updatedDraft.Status != "failed" {
		t.Errorf("Expected draft status 'failed', got '%s'", updatedDraft.Status)
	}
}

// TestPostDraftToThreads_RateLimited tests handling of Threads rate limiting
func TestPostDraftToThreads_RateLimited(t *testing.T) {
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), userID, "repo-456",
		"Test content", "Test content")

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
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), userID, "repo-456",
		"Test content", "Test content")

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
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"

	// Create content that exceeds Threads 500 char limit
	longContent := make([]byte, 600)
	for i := range longContent {
		longContent[i] = 'a'
	}

	draft, _ := draftStore.CreateDraft(context.Background(), userID, "repo-456",
		string(longContent), string(longContent))

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
	// Implementation complete (alice-68)

	draftStore := NewMockDraftStoreForPost()
	postStore := NewMockPostStoreForThreads()
	threadsClient := NewMockThreadsClient()
	credStore := NewMockCredentialStoreForThreads()

	userID := "user-123"
	draft, _ := draftStore.CreateDraft(context.Background(), userID, "repo-456",
		"Test content", "Test content")

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
