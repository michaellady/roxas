package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// =============================================================================
// Mock Stores for GitHub App Webhook Tests
// =============================================================================

// MockInstallationStore is an in-memory installation store for testing
type MockInstallationStore struct {
	mu            sync.Mutex
	installations map[int64]*InstallationRecord
	deleted       map[int64]bool
	suspended     map[int64]bool
	nextID        int
}

func NewMockInstallationStore() *MockInstallationStore {
	return &MockInstallationStore{
		installations: make(map[int64]*InstallationRecord),
		deleted:       make(map[int64]bool),
		suspended:     make(map[int64]bool),
		nextID:        1,
	}
}

func (m *MockInstallationStore) UpsertInstallation(ctx context.Context, inst *InstallationRecord) (*InstallationRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := &InstallationRecord{
		ID:             generateTestID("inst", m.nextID),
		InstallationID: inst.InstallationID,
		UserID:         inst.UserID,
		AccountLogin:   inst.AccountLogin,
		AccountID:      inst.AccountID,
		AccountType:    inst.AccountType,
	}
	m.nextID++
	m.installations[inst.InstallationID] = result
	return result, nil
}

func (m *MockInstallationStore) DeleteInstallation(ctx context.Context, installationID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleted[installationID] = true
	delete(m.installations, installationID)
	return nil
}

func (m *MockInstallationStore) SuspendInstallation(ctx context.Context, installationID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.suspended[installationID] = true
	return nil
}

func (m *MockInstallationStore) UnsuspendInstallation(ctx context.Context, installationID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.suspended, installationID)
	return nil
}

func (m *MockInstallationStore) GetInstallationByID(ctx context.Context, installationID int64) (*InstallationRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.installations[installationID], nil
}

func (m *MockInstallationStore) GetInstallations() map[int64]*InstallationRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[int64]*InstallationRecord, len(m.installations))
	for k, v := range m.installations {
		result[k] = v
	}
	return result
}

func (m *MockInstallationStore) IsDeleted(installationID int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deleted[installationID]
}

func (m *MockInstallationStore) IsSuspended(installationID int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.suspended[installationID]
}

// MockAppRepositoryStore is an in-memory app repository store for testing
type MockAppRepositoryStore struct {
	mu       sync.Mutex
	repos    map[int64]*AppRepositoryRecord // keyed by GitHubRepoID
	removed  map[string]bool                // keyed by "installationID:githubRepoID"
	nextID   int
}

func NewMockAppRepositoryStore() *MockAppRepositoryStore {
	return &MockAppRepositoryStore{
		repos:   make(map[int64]*AppRepositoryRecord),
		removed: make(map[string]bool),
		nextID:  1,
	}
}

func (m *MockAppRepositoryStore) UpsertAppRepository(ctx context.Context, repo *AppRepositoryRecord) (*AppRepositoryRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := &AppRepositoryRecord{
		ID:             generateTestID("apprepo", m.nextID),
		InstallationID: repo.InstallationID,
		GitHubRepoID:   repo.GitHubRepoID,
		FullName:       repo.FullName,
		HTMLURL:        repo.HTMLURL,
		Private:        repo.Private,
		DefaultBranch:  repo.DefaultBranch,
		IsActive:       true,
	}
	m.nextID++
	m.repos[repo.GitHubRepoID] = result
	return result, nil
}

func (m *MockAppRepositoryStore) RemoveAppRepository(ctx context.Context, installationID, githubRepoID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := formatRemoveKey(installationID, githubRepoID)
	m.removed[key] = true
	if repo, ok := m.repos[githubRepoID]; ok {
		repo.IsActive = false
	}
	return nil
}

func (m *MockAppRepositoryStore) GetByGitHubRepoID(ctx context.Context, githubRepoID int64) (*AppRepositoryRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	repo := m.repos[githubRepoID]
	if repo != nil && !repo.IsActive {
		return nil, nil
	}
	return repo, nil
}

func (m *MockAppRepositoryStore) GetRepos() map[int64]*AppRepositoryRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[int64]*AppRepositoryRecord, len(m.repos))
	for k, v := range m.repos {
		result[k] = v
	}
	return result
}

func (m *MockAppRepositoryStore) AddRepo(repo *AppRepositoryRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.repos[repo.GitHubRepoID] = repo
}

func formatRemoveKey(installationID, githubRepoID int64) string {
	return string(rune(installationID)) + ":" + string(rune(githubRepoID))
}

// MockGitHubAppRepoStore extends the mock repo store with GetRepositoryByAppRepoID
type MockGitHubAppRepoStore struct {
	mu              sync.Mutex
	repos           map[string]*Repository // by repo ID
	reposByAppRepoID map[string]*Repository // by app repo ID
}

func NewMockGitHubAppRepoStore() *MockGitHubAppRepoStore {
	return &MockGitHubAppRepoStore{
		repos:            make(map[string]*Repository),
		reposByAppRepoID: make(map[string]*Repository),
	}
}

func (m *MockGitHubAppRepoStore) GetRepositoryByID(ctx context.Context, repoID string) (*Repository, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.repos[repoID], nil
}

func (m *MockGitHubAppRepoStore) GetRepositoryByAppRepoID(ctx context.Context, appRepoID string) (*Repository, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reposByAppRepoID[appRepoID], nil
}

func (m *MockGitHubAppRepoStore) AddRepository(repo *Repository) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.repos[repo.ID] = repo
}

func (m *MockGitHubAppRepoStore) LinkAppRepoID(appRepoID string, repo *Repository) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reposByAppRepoID[appRepoID] = repo
}

// =============================================================================
// Test Helpers
// =============================================================================

func createGitHubAppWebhookRequest(t *testing.T, payload []byte, signature, eventType, deliveryID string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/webhooks/github-app", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	if signature != "" {
		req.Header.Set("X-Hub-Signature-256", signature)
	}
	if eventType != "" {
		req.Header.Set("X-GitHub-Event", eventType)
	}
	if deliveryID != "" {
		req.Header.Set("X-GitHub-Delivery", deliveryID)
	}

	return req
}

func newTestGitHubAppHandler(secret string) (*GitHubAppWebhookHandler, *MockInstallationStore, *MockAppRepositoryStore, *MockGitHubAppRepoStore, *MockDraftWebhookStore, *MockIdempotencyStore) {
	instStore := NewMockInstallationStore()
	appRepoStore := NewMockAppRepositoryStore()
	repoStore := NewMockGitHubAppRepoStore()
	draftStore := NewMockDraftWebhookStore()
	idempotencyStore := NewMockIdempotencyStore()

	handler := NewGitHubAppWebhookHandler(secret, instStore, appRepoStore, repoStore, draftStore, idempotencyStore)
	return handler, instStore, appRepoStore, repoStore, draftStore, idempotencyStore
}

// =============================================================================
// Tests
// =============================================================================

func TestGitHubAppWebhook_PingEvent(t *testing.T) {
	secret := "test-app-secret"
	handler, _, _, _, _, _ := newTestGitHubAppHandler(secret)

	payload := createPingPayload()
	signature := generateGitHubSignature(payload, secret)

	req := createGitHubAppWebhookRequest(t, payload, signature, "ping", "delivery-ping-1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp GitHubAppWebhookResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp.Message != "pong" {
		t.Errorf("Expected message 'pong', got '%s'", resp.Message)
	}
}

func TestGitHubAppWebhook_MissingSignature(t *testing.T) {
	secret := "test-app-secret"
	handler, _, _, _, _, _ := newTestGitHubAppHandler(secret)

	payload := createPingPayload()

	req := createGitHubAppWebhookRequest(t, payload, "", "ping", "delivery-1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp.Error != "missing signature" {
		t.Errorf("Expected error 'missing signature', got '%s'", resp.Error)
	}
}

func TestGitHubAppWebhook_InvalidSignature(t *testing.T) {
	secret := "test-app-secret"
	handler, _, _, _, _, _ := newTestGitHubAppHandler(secret)

	payload := createPingPayload()
	// Sign with wrong secret
	signature := generateGitHubSignature(payload, "wrong-secret")

	req := createGitHubAppWebhookRequest(t, payload, signature, "ping", "delivery-1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp.Error != "invalid signature" {
		t.Errorf("Expected error 'invalid signature', got '%s'", resp.Error)
	}
}

func TestGitHubAppWebhook_InstallationCreated(t *testing.T) {
	secret := "test-app-secret"
	handler, instStore, appRepoStore, _, _, _ := newTestGitHubAppHandler(secret)

	payload := map[string]interface{}{
		"action": "created",
		"installation": map[string]interface{}{
			"id": 12345,
			"account": map[string]interface{}{
				"login": "test-org",
				"id":    67890,
				"type":  "Organization",
			},
		},
		"sender": map[string]interface{}{
			"login": "test-user",
			"id":    11111,
		},
		"repositories": []map[string]interface{}{
			{
				"id":             100,
				"full_name":      "test-org/repo-a",
				"private":        false,
				"default_branch": "main",
			},
			{
				"id":             101,
				"full_name":      "test-org/repo-b",
				"private":        true,
				"default_branch": "develop",
			},
		},
	}
	body, _ := json.Marshal(payload)
	signature := generateGitHubSignature(body, secret)

	req := createGitHubAppWebhookRequest(t, body, signature, "installation", "delivery-inst-1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify installation was stored
	installations := instStore.GetInstallations()
	if len(installations) != 1 {
		t.Fatalf("Expected 1 installation, got %d", len(installations))
	}
	inst, ok := installations[12345]
	if !ok {
		t.Fatal("Expected installation with ID 12345")
	}
	if inst.AccountLogin != "test-org" {
		t.Errorf("Expected account login 'test-org', got '%s'", inst.AccountLogin)
	}
	if inst.AccountID != 67890 {
		t.Errorf("Expected account ID 67890, got %d", inst.AccountID)
	}
	if inst.AccountType != "Organization" {
		t.Errorf("Expected account type 'Organization', got '%s'", inst.AccountType)
	}

	// Verify repositories were stored
	repos := appRepoStore.GetRepos()
	if len(repos) != 2 {
		t.Fatalf("Expected 2 app repos, got %d", len(repos))
	}
	repoA, ok := repos[100]
	if !ok {
		t.Fatal("Expected app repo with GitHub repo ID 100")
	}
	if repoA.FullName != "test-org/repo-a" {
		t.Errorf("Expected full name 'test-org/repo-a', got '%s'", repoA.FullName)
	}
}

func TestGitHubAppWebhook_PushCreatingDraft(t *testing.T) {
	secret := "test-app-secret"
	handler, _, appRepoStore, repoStore, draftStore, idempotencyStore := newTestGitHubAppHandler(secret)

	// Set up an app repo and a linked repository
	appRepo := &AppRepositoryRecord{
		ID:             "apprepo-1",
		InstallationID: 12345,
		GitHubRepoID:   200,
		FullName:       "test-org/my-repo",
		HTMLURL:        "https://github.com/test-org/my-repo",
		IsActive:       true,
	}
	appRepoStore.AddRepo(appRepo)

	linkedRepo := &Repository{
		ID:            "repo-linked-1",
		UserID:        "user-789",
		GitHubURL:     "https://github.com/test-org/my-repo",
		WebhookSecret: "unused-for-app",
	}
	repoStore.AddRepository(linkedRepo)
	repoStore.LinkAppRepoID("apprepo-1", linkedRepo)

	payload := map[string]interface{}{
		"ref":    "refs/heads/main",
		"before": "aaa000",
		"after":  "bbb111",
		"installation": map[string]interface{}{
			"id": 12345,
		},
		"repository": map[string]interface{}{
			"id":        200,
			"full_name": "test-org/my-repo",
			"html_url":  "https://github.com/test-org/my-repo",
		},
		"commits": []map[string]interface{}{
			{
				"id":      "commit-sha-1",
				"message": "feat: add webhook handler",
				"url":     "https://github.com/test-org/my-repo/commit/commit-sha-1",
				"author":  map[string]interface{}{"name": "Dev", "email": "dev@example.com"},
			},
		},
	}
	body, _ := json.Marshal(payload)
	signature := generateGitHubSignature(body, secret)

	req := createGitHubAppWebhookRequest(t, body, signature, "push", "delivery-push-1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify response
	var resp GitHubAppWebhookResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp.Message != "draft created" {
		t.Errorf("Expected message 'draft created', got '%s'", resp.Message)
	}
	if resp.DraftID == "" {
		t.Error("Expected non-empty draft ID in response")
	}

	// Verify draft was created
	drafts := draftStore.GetDrafts()
	if len(drafts) != 1 {
		t.Fatalf("Expected 1 draft, got %d", len(drafts))
	}
	draft := drafts[0]
	if draft.UserID != "user-789" {
		t.Errorf("Expected user ID 'user-789', got '%s'", draft.UserID)
	}
	if draft.RepositoryID != "repo-linked-1" {
		t.Errorf("Expected repository ID 'repo-linked-1', got '%s'", draft.RepositoryID)
	}
	if draft.Ref != "refs/heads/main" {
		t.Errorf("Expected ref 'refs/heads/main', got '%s'", draft.Ref)
	}
	if draft.BeforeSHA != "aaa000" {
		t.Errorf("Expected before SHA 'aaa000', got '%s'", draft.BeforeSHA)
	}
	if draft.AfterSHA != "bbb111" {
		t.Errorf("Expected after SHA 'bbb111', got '%s'", draft.AfterSHA)
	}
	if len(draft.CommitSHAs) != 1 || draft.CommitSHAs[0] != "commit-sha-1" {
		t.Errorf("Expected commit SHAs ['commit-sha-1'], got %v", draft.CommitSHAs)
	}

	// Verify idempotency was recorded
	if !idempotencyStore.IsProcessed("delivery-push-1") {
		t.Error("Expected delivery ID to be marked as processed")
	}
}

func TestGitHubAppWebhook_UnknownEventAcknowledged(t *testing.T) {
	secret := "test-app-secret"
	handler, _, _, _, _, _ := newTestGitHubAppHandler(secret)

	payload := []byte(`{"action":"something"}`)
	signature := generateGitHubSignature(payload, secret)

	req := createGitHubAppWebhookRequest(t, payload, signature, "some_unknown_event", "delivery-unk-1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for unknown event, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp GitHubAppWebhookResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", resp.Status)
	}
	if resp.Message != "event acknowledged" {
		t.Errorf("Expected message 'event acknowledged', got '%s'", resp.Message)
	}
}
