package handlers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// Mock Stores for Multi-Tenant Webhook Tests
// =============================================================================

// MockWebhookRepositoryStore is an in-memory repository store for testing
type MockWebhookRepositoryStore struct {
	mu    sync.Mutex
	repos map[string]*Repository
}

// NewMockWebhookRepositoryStore creates a new mock repository store
func NewMockWebhookRepositoryStore() *MockWebhookRepositoryStore {
	return &MockWebhookRepositoryStore{
		repos: make(map[string]*Repository),
	}
}

// AddRepository adds a repository to the mock store
func (m *MockWebhookRepositoryStore) AddRepository(repo *Repository) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.repos[repo.ID] = repo
}

// GetRepositoryByID retrieves a repository by ID
func (m *MockWebhookRepositoryStore) GetRepositoryByID(ctx context.Context, repoID string) (*Repository, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if repo, ok := m.repos[repoID]; ok {
		return repo, nil
	}
	return nil, nil
}

// MockCommitStore is an in-memory commit store for testing
type MockCommitStore struct {
	mu      sync.Mutex
	commits map[string]*StoredCommit // key: repoID + sha
}

// NewMockCommitStore creates a new mock commit store
func NewMockCommitStore() *MockCommitStore {
	return &MockCommitStore{
		commits: make(map[string]*StoredCommit),
	}
}

// StoreCommit stores a commit in the mock store
func (m *MockCommitStore) StoreCommit(ctx context.Context, commit *StoredCommit) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := commit.RepositoryID + ":" + commit.CommitSHA
	m.commits[key] = commit
	return nil
}

// GetCommitBySHA retrieves a commit by repository ID and SHA
func (m *MockCommitStore) GetCommitBySHA(ctx context.Context, repoID, sha string) (*StoredCommit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := repoID + ":" + sha
	if commit, ok := m.commits[key]; ok {
		return commit, nil
	}
	return nil, nil
}

// GetStoredCommits returns all stored commits (for test assertions)
func (m *MockCommitStore) GetStoredCommits() []*StoredCommit {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]*StoredCommit, 0, len(m.commits))
	for _, c := range m.commits {
		result = append(result, c)
	}
	return result
}

// =============================================================================
// Test Helpers
// =============================================================================

// generateGitHubSignature creates a GitHub-style HMAC-SHA256 signature
func generateGitHubSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// createWebhookRequest creates a webhook request with optional signature
func createWebhookRequest(t *testing.T, repoID string, payload []byte, signature string) *http.Request {
	t.Helper()

	url := "/webhooks/github/" + repoID
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	if signature != "" {
		req.Header.Set("X-Hub-Signature-256", signature)
	}

	return req
}

// createPushPayload creates a GitHub push event payload
func createPushPayload(commits []map[string]interface{}) []byte {
	payload := map[string]interface{}{
		"ref": "refs/heads/main",
		"repository": map[string]interface{}{
			"html_url":  "https://github.com/test/repo",
			"full_name": "test/repo",
		},
		"commits": commits,
	}
	data, _ := json.Marshal(payload)
	return data
}

// createPingPayload creates a GitHub ping event payload
func createPingPayload() []byte {
	payload := map[string]interface{}{
		"zen":     "Keep it logically awesome.",
		"hook_id": 12345,
		"hook": map[string]interface{}{
			"type": "Repository",
			"id":   12345,
		},
		"repository": map[string]interface{}{
			"html_url":  "https://github.com/test/repo",
			"full_name": "test/repo",
		},
	}
	data, _ := json.Marshal(payload)
	return data
}

// =============================================================================
// TB12 Tests: Multi-Tenant Webhook Handler (TDD - RED)
// =============================================================================

// TestMultiTenantWebhookValidSignature tests valid webhook with correct signature
func TestMultiTenantWebhookValidSignature(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	commitStore := NewMockCommitStore()

	// Add a repository with known secret
	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-webhook-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	handler := NewMultiTenantWebhookHandler(repoStore, commitStore)

	// Create push payload with one commit
	commits := []map[string]interface{}{
		{
			"id":        "abc123def456",
			"message":   "feat: add new feature",
			"url":       "https://github.com/test/repo/commit/abc123def456",
			"timestamp": "2024-01-15T10:30:00Z",
			"author": map[string]interface{}{
				"name":  "Test Author",
				"email": "test@example.com",
			},
		},
	}
	payload := createPushPayload(commits)
	signature := generateGitHubSignature(payload, repo.WebhookSecret)

	req := createWebhookRequest(t, repo.ID, payload, signature)
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify commit was stored
	storedCommits := commitStore.GetStoredCommits()
	if len(storedCommits) != 1 {
		t.Errorf("Expected 1 commit stored, got %d", len(storedCommits))
	}

	if len(storedCommits) > 0 {
		if storedCommits[0].CommitSHA != "abc123def456" {
			t.Errorf("Expected commit SHA abc123def456, got %s", storedCommits[0].CommitSHA)
		}
		if storedCommits[0].RepositoryID != repo.ID {
			t.Errorf("Expected repository ID %s, got %s", repo.ID, storedCommits[0].RepositoryID)
		}
	}
}

// TestMultiTenantWebhookInvalidSignature tests that invalid signature returns 401
func TestMultiTenantWebhookInvalidSignature(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	commitStore := NewMockCommitStore()

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "correct-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	handler := NewMultiTenantWebhookHandler(repoStore, commitStore)

	commits := []map[string]interface{}{
		{"id": "abc123", "message": "test", "author": map[string]interface{}{"name": "Test"}},
	}
	payload := createPushPayload(commits)

	// Sign with WRONG secret
	wrongSignature := generateGitHubSignature(payload, "wrong-secret")

	req := createWebhookRequest(t, repo.ID, payload, wrongSignature)
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify no commits stored
	storedCommits := commitStore.GetStoredCommits()
	if len(storedCommits) != 0 {
		t.Errorf("Expected 0 commits stored, got %d", len(storedCommits))
	}
}

// TestMultiTenantWebhookNonExistentRepo tests that non-existent repo returns 404
func TestMultiTenantWebhookNonExistentRepo(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	commitStore := NewMockCommitStore()

	// Do NOT add any repository to the store

	handler := NewMultiTenantWebhookHandler(repoStore, commitStore)

	commits := []map[string]interface{}{
		{"id": "abc123", "message": "test", "author": map[string]interface{}{"name": "Test"}},
	}
	payload := createPushPayload(commits)
	signature := generateGitHubSignature(payload, "any-secret")

	req := createWebhookRequest(t, "nonexistent-repo-id", payload, signature)
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 Not Found, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestMultiTenantWebhookMalformedPayload tests that malformed JSON returns 400
func TestMultiTenantWebhookMalformedPayload(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	commitStore := NewMockCommitStore()

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	handler := NewMultiTenantWebhookHandler(repoStore, commitStore)

	// Malformed JSON payload
	payload := []byte(`{invalid json truncated`)
	signature := generateGitHubSignature(payload, repo.WebhookSecret)

	req := createWebhookRequest(t, repo.ID, payload, signature)
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 Bad Request, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestMultiTenantWebhookPingEvent tests that ping event returns 200 without storing
func TestMultiTenantWebhookPingEvent(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	commitStore := NewMockCommitStore()

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	handler := NewMultiTenantWebhookHandler(repoStore, commitStore)

	payload := createPingPayload()
	signature := generateGitHubSignature(payload, repo.WebhookSecret)

	req := createWebhookRequest(t, repo.ID, payload, signature)
	req.Header.Set("X-GitHub-Event", "ping")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify NO commits stored (ping events don't have commits)
	storedCommits := commitStore.GetStoredCommits()
	if len(storedCommits) != 0 {
		t.Errorf("Expected 0 commits stored for ping event, got %d", len(storedCommits))
	}
}

// TestMultiTenantWebhookMultipleCommits tests that multiple commits are all stored
func TestMultiTenantWebhookMultipleCommits(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	commitStore := NewMockCommitStore()

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	handler := NewMultiTenantWebhookHandler(repoStore, commitStore)

	// Create push payload with multiple commits
	commits := []map[string]interface{}{
		{
			"id":        "commit-sha-1",
			"message":   "feat: first commit",
			"url":       "https://github.com/test/repo/commit/commit-sha-1",
			"timestamp": "2024-01-15T10:30:00Z",
			"author":    map[string]interface{}{"name": "Author One"},
		},
		{
			"id":        "commit-sha-2",
			"message":   "fix: second commit",
			"url":       "https://github.com/test/repo/commit/commit-sha-2",
			"timestamp": "2024-01-15T10:31:00Z",
			"author":    map[string]interface{}{"name": "Author Two"},
		},
		{
			"id":        "commit-sha-3",
			"message":   "docs: third commit",
			"url":       "https://github.com/test/repo/commit/commit-sha-3",
			"timestamp": "2024-01-15T10:32:00Z",
			"author":    map[string]interface{}{"name": "Author Three"},
		},
	}
	payload := createPushPayload(commits)
	signature := generateGitHubSignature(payload, repo.WebhookSecret)

	req := createWebhookRequest(t, repo.ID, payload, signature)
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify all 3 commits were stored
	storedCommits := commitStore.GetStoredCommits()
	if len(storedCommits) != 3 {
		t.Errorf("Expected 3 commits stored, got %d", len(storedCommits))
	}
}

// TestMultiTenantWebhookMissingSignature tests that missing signature returns 401
func TestMultiTenantWebhookMissingSignature(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	commitStore := NewMockCommitStore()

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	handler := NewMultiTenantWebhookHandler(repoStore, commitStore)

	commits := []map[string]interface{}{
		{"id": "abc123", "message": "test", "author": map[string]interface{}{"name": "Test"}},
	}
	payload := createPushPayload(commits)

	// No signature
	req := createWebhookRequest(t, repo.ID, payload, "")
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestMultiTenantWebhookUsesPerRepoSecret tests that each repo uses its own secret
func TestMultiTenantWebhookUsesPerRepoSecret(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	commitStore := NewMockCommitStore()

	// Add two repos with different secrets
	repo1 := &Repository{
		ID:            "repo-1",
		UserID:        "user-1",
		GitHubURL:     "https://github.com/user1/repo",
		WebhookSecret: "secret-for-repo-1",
		CreatedAt:     time.Now(),
	}
	repo2 := &Repository{
		ID:            "repo-2",
		UserID:        "user-2",
		GitHubURL:     "https://github.com/user2/repo",
		WebhookSecret: "secret-for-repo-2",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo1)
	repoStore.AddRepository(repo2)

	handler := NewMultiTenantWebhookHandler(repoStore, commitStore)

	commits := []map[string]interface{}{
		{"id": "abc123", "message": "test", "author": map[string]interface{}{"name": "Test"}},
	}
	payload := createPushPayload(commits)

	// Sign with repo1's secret, send to repo2 - should fail
	signatureForRepo1 := generateGitHubSignature(payload, repo1.WebhookSecret)

	req := createWebhookRequest(t, repo2.ID, payload, signatureForRepo1)
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 (wrong secret for repo), got %d: %s", rr.Code, rr.Body.String())
	}

	// Now sign with repo2's correct secret - should succeed
	signatureForRepo2 := generateGitHubSignature(payload, repo2.WebhookSecret)

	req2 := createWebhookRequest(t, repo2.ID, payload, signatureForRepo2)
	req2.Header.Set("X-GitHub-Event", "push")

	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Errorf("Expected status 200 (correct secret for repo), got %d: %s", rr2.Code, rr2.Body.String())
	}
}

// TestMultiTenantWebhookReturnsJSON tests that responses are JSON formatted
func TestMultiTenantWebhookReturnsJSON(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	commitStore := NewMockCommitStore()

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	handler := NewMultiTenantWebhookHandler(repoStore, commitStore)

	commits := []map[string]interface{}{
		{"id": "abc123", "message": "test", "author": map[string]interface{}{"name": "Test"}},
	}
	payload := createPushPayload(commits)
	signature := generateGitHubSignature(payload, repo.WebhookSecret)

	req := createWebhookRequest(t, repo.ID, payload, signature)
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}
}

// =============================================================================
// Mock Delivery Store for Webhook Delivery Recording Tests
// =============================================================================

// MockDeliveryStore is an in-memory delivery store for testing
type MockDeliveryStore struct {
	mu         sync.Mutex
	deliveries []*WebhookDelivery
}

// WebhookDelivery represents a recorded webhook delivery
type WebhookDelivery struct {
	RepositoryID string
	EventType    string
	Payload      []byte
	StatusCode   int
	ErrorMessage string
	Success      bool
}

// NewMockDeliveryStore creates a new mock delivery store
func NewMockDeliveryStore() *MockDeliveryStore {
	return &MockDeliveryStore{
		deliveries: make([]*WebhookDelivery, 0),
	}
}

// RecordDelivery records a webhook delivery
func (m *MockDeliveryStore) RecordDelivery(ctx context.Context, repoID, eventType string, payload []byte, statusCode int, errorMessage string, success bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.deliveries = append(m.deliveries, &WebhookDelivery{
		RepositoryID: repoID,
		EventType:    eventType,
		Payload:      payload,
		StatusCode:   statusCode,
		ErrorMessage: errorMessage,
		Success:      success,
	})
	return nil
}

// GetDeliveries returns all recorded deliveries
func (m *MockDeliveryStore) GetDeliveries() []*WebhookDelivery {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]*WebhookDelivery, len(m.deliveries))
	copy(result, m.deliveries)
	return result
}

// =============================================================================
// Webhook Delivery Recording Tests (TDD - RED → GREEN)
// =============================================================================

// TestMultiTenantWebhookRecordsDeliveryOnMissingSignature tests that delivery
// is recorded with eventType even when signature is missing (auth failure)
func TestMultiTenantWebhookRecordsDeliveryOnMissingSignature(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	commitStore := NewMockCommitStore()
	deliveryStore := NewMockDeliveryStore()

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	handler := NewMultiTenantWebhookHandlerWithDelivery(repoStore, commitStore, deliveryStore)

	commits := []map[string]interface{}{
		{"id": "abc123", "message": "test", "author": map[string]interface{}{"name": "Test"}},
	}
	payload := createPushPayload(commits)

	// No signature - this is an auth failure
	req := createWebhookRequest(t, repo.ID, payload, "")
	req.Header.Set("X-GitHub-Event", "push") // Event type IS set

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should return 401
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d", rr.Code)
	}

	// Delivery should be recorded with eventType = "push", NOT empty
	deliveries := deliveryStore.GetDeliveries()
	if len(deliveries) != 1 {
		t.Fatalf("Expected 1 delivery recorded, got %d", len(deliveries))
	}

	delivery := deliveries[0]
	if delivery.EventType != "push" {
		t.Errorf("Expected eventType 'push', got '%s' (BUG: eventType is empty on auth failures)", delivery.EventType)
	}
	if delivery.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got %d", delivery.StatusCode)
	}
	if delivery.Success {
		t.Error("Expected success=false for auth failure")
	}
}

// TestMultiTenantWebhookRecordsDeliveryOnInvalidSignature tests that delivery
// is recorded with eventType even when signature is invalid (auth failure)
func TestMultiTenantWebhookRecordsDeliveryOnInvalidSignature(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	commitStore := NewMockCommitStore()
	deliveryStore := NewMockDeliveryStore()

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "correct-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	handler := NewMultiTenantWebhookHandlerWithDelivery(repoStore, commitStore, deliveryStore)

	commits := []map[string]interface{}{
		{"id": "abc123", "message": "test", "author": map[string]interface{}{"name": "Test"}},
	}
	payload := createPushPayload(commits)

	// Sign with WRONG secret
	wrongSignature := generateGitHubSignature(payload, "wrong-secret")

	req := createWebhookRequest(t, repo.ID, payload, wrongSignature)
	req.Header.Set("X-GitHub-Event", "push") // Event type IS set

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should return 401
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d", rr.Code)
	}

	// Delivery should be recorded with eventType = "push", NOT empty
	deliveries := deliveryStore.GetDeliveries()
	if len(deliveries) != 1 {
		t.Fatalf("Expected 1 delivery recorded, got %d", len(deliveries))
	}

	delivery := deliveries[0]
	if delivery.EventType != "push" {
		t.Errorf("Expected eventType 'push', got '%s' (BUG: eventType is empty on auth failures)", delivery.EventType)
	}
	if delivery.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got %d", delivery.StatusCode)
	}
}

// TestMultiTenantWebhookRecordsDeliveryOnSuccess tests that delivery
// is recorded with eventType on successful webhook processing
func TestMultiTenantWebhookRecordsDeliveryOnSuccess(t *testing.T) {
	repoStore := NewMockWebhookRepositoryStore()
	commitStore := NewMockCommitStore()
	deliveryStore := NewMockDeliveryStore()

	repo := &Repository{
		ID:            "repo-123",
		UserID:        "user-456",
		GitHubURL:     "https://github.com/test/repo",
		WebhookSecret: "test-secret",
		CreatedAt:     time.Now(),
	}
	repoStore.AddRepository(repo)

	handler := NewMultiTenantWebhookHandlerWithDelivery(repoStore, commitStore, deliveryStore)

	commits := []map[string]interface{}{
		{"id": "abc123", "message": "test", "author": map[string]interface{}{"name": "Test"}},
	}
	payload := createPushPayload(commits)
	signature := generateGitHubSignature(payload, repo.WebhookSecret)

	req := createWebhookRequest(t, repo.ID, payload, signature)
	req.Header.Set("X-GitHub-Event", "push")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should return 200
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d", rr.Code)
	}

	// Delivery should be recorded
	deliveries := deliveryStore.GetDeliveries()
	if len(deliveries) != 1 {
		t.Fatalf("Expected 1 delivery recorded, got %d", len(deliveries))
	}

	delivery := deliveries[0]
	if delivery.EventType != "push" {
		t.Errorf("Expected eventType 'push', got '%s'", delivery.EventType)
	}
	if delivery.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", delivery.StatusCode)
	}
	if !delivery.Success {
		t.Error("Expected success=true for successful processing")
	}
}
