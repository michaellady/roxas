package services

import (
	"context"
	"errors"
	"testing"
)

// =============================================================================
// Mock GitHub Client for Testing
// =============================================================================

type mockGitHubClient struct {
	CreateWebhookFunc func(ctx context.Context, owner, repo string, config GitHubWebhookConfig) (*GitHubWebhook, error)
	DeleteWebhookFunc func(ctx context.Context, owner, repo string, webhookID int64) error
	GetRepoFunc       func(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error)

	CreateWebhookCalls []struct {
		Owner  string
		Repo   string
		Config GitHubWebhookConfig
	}
	DeleteWebhookCalls []struct {
		Owner     string
		Repo      string
		WebhookID int64
	}
	GetRepoCalls []struct {
		Owner string
		Repo  string
	}
}

func newMockGitHubClient() *mockGitHubClient {
	return &mockGitHubClient{
		CreateWebhookCalls: []struct {
			Owner  string
			Repo   string
			Config GitHubWebhookConfig
		}{},
		DeleteWebhookCalls: []struct {
			Owner     string
			Repo      string
			WebhookID int64
		}{},
		GetRepoCalls: []struct {
			Owner string
			Repo  string
		}{},
	}
}

func (m *mockGitHubClient) CreateWebhook(ctx context.Context, owner, repo string, config GitHubWebhookConfig) (*GitHubWebhook, error) {
	m.CreateWebhookCalls = append(m.CreateWebhookCalls, struct {
		Owner  string
		Repo   string
		Config GitHubWebhookConfig
	}{Owner: owner, Repo: repo, Config: config})

	if m.CreateWebhookFunc != nil {
		return m.CreateWebhookFunc(ctx, owner, repo, config)
	}
	return &GitHubWebhook{ID: 12345, Active: true}, nil
}

func (m *mockGitHubClient) DeleteWebhook(ctx context.Context, owner, repo string, webhookID int64) error {
	m.DeleteWebhookCalls = append(m.DeleteWebhookCalls, struct {
		Owner     string
		Repo      string
		WebhookID int64
	}{Owner: owner, Repo: repo, WebhookID: webhookID})

	if m.DeleteWebhookFunc != nil {
		return m.DeleteWebhookFunc(ctx, owner, repo, webhookID)
	}
	return nil
}

func (m *mockGitHubClient) GetRepo(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error) {
	m.GetRepoCalls = append(m.GetRepoCalls, struct {
		Owner string
		Repo  string
	}{Owner: owner, Repo: repo})

	if m.GetRepoFunc != nil {
		return m.GetRepoFunc(ctx, owner, repo)
	}
	return &GitHubRepoInfo{ID: 98765, FullName: owner + "/" + repo, IsPrivate: false}, nil
}

// =============================================================================
// Mock Client Factory
// =============================================================================

type mockClientFactory struct {
	client GitHubWebhookClient
}

func newMockClientFactory(client GitHubWebhookClient) *mockClientFactory {
	return &mockClientFactory{client: client}
}

func (f *mockClientFactory) NewClient(accessToken string) GitHubWebhookClient {
	return f.client
}

// =============================================================================
// Mock Metadata Store
// =============================================================================

type mockMetadataStore struct {
	UpdateWebhookIDFunc func(ctx context.Context, repoID string, webhookID int64) error
	ClearWebhookIDFunc  func(ctx context.Context, repoID string) error

	UpdateWebhookIDCalls []struct {
		RepoID    string
		WebhookID int64
	}
	ClearWebhookIDCalls []struct {
		RepoID string
	}
}

func newMockMetadataStore() *mockMetadataStore {
	return &mockMetadataStore{
		UpdateWebhookIDCalls: []struct {
			RepoID    string
			WebhookID int64
		}{},
		ClearWebhookIDCalls: []struct {
			RepoID string
		}{},
	}
}

func (m *mockMetadataStore) UpdateWebhookID(ctx context.Context, repoID string, webhookID int64) error {
	m.UpdateWebhookIDCalls = append(m.UpdateWebhookIDCalls, struct {
		RepoID    string
		WebhookID int64
	}{RepoID: repoID, WebhookID: webhookID})

	if m.UpdateWebhookIDFunc != nil {
		return m.UpdateWebhookIDFunc(ctx, repoID, webhookID)
	}
	return nil
}

func (m *mockMetadataStore) ClearWebhookID(ctx context.Context, repoID string) error {
	m.ClearWebhookIDCalls = append(m.ClearWebhookIDCalls, struct {
		RepoID string
	}{RepoID: repoID})

	if m.ClearWebhookIDFunc != nil {
		return m.ClearWebhookIDFunc(ctx, repoID)
	}
	return nil
}

// =============================================================================
// Tests for InstallWebhook
// =============================================================================

func TestInstallWebhook_Success(t *testing.T) {
	mockClient := newMockGitHubClient()
	mockClient.GetRepoFunc = func(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error) {
		return &GitHubRepoInfo{ID: 98765, FullName: owner + "/" + repo}, nil
	}
	mockClient.CreateWebhookFunc = func(ctx context.Context, owner, repo string, config GitHubWebhookConfig) (*GitHubWebhook, error) {
		return &GitHubWebhook{ID: 12345, Active: true}, nil
	}

	mockStore := newMockMetadataStore()
	factory := newMockClientFactory(mockClient)
	service := NewWebhookService(factory, mockStore)

	result, err := service.InstallWebhook(context.Background(), "test-token", RepoInstallRequest{
		RepositoryID:  "repo-uuid-123",
		Owner:         "michaellady",
		Repo:          "roxas",
		WebhookURL:    "https://api.roxas.dev/webhook/repo-uuid-123",
		WebhookSecret: "webhook-secret",
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}

	if result.WebhookID != 12345 {
		t.Errorf("Expected webhook ID 12345, got %d", result.WebhookID)
	}

	if result.GitHubRepoID != 98765 {
		t.Errorf("Expected GitHub repo ID 98765, got %d", result.GitHubRepoID)
	}

	// Verify GetRepo was called
	if len(mockClient.GetRepoCalls) != 1 {
		t.Errorf("Expected 1 GetRepo call, got %d", len(mockClient.GetRepoCalls))
	}

	// Verify CreateWebhook was called
	if len(mockClient.CreateWebhookCalls) != 1 {
		t.Errorf("Expected 1 CreateWebhook call, got %d", len(mockClient.CreateWebhookCalls))
	}

	call := mockClient.CreateWebhookCalls[0]
	if call.Owner != "michaellady" || call.Repo != "roxas" {
		t.Errorf("Expected owner/repo michaellady/roxas, got %s/%s", call.Owner, call.Repo)
	}

	if call.Config.Secret != "webhook-secret" {
		t.Errorf("Expected secret webhook-secret, got %s", call.Config.Secret)
	}

	// Verify metadata store was called
	if len(mockStore.UpdateWebhookIDCalls) != 1 {
		t.Errorf("Expected 1 UpdateWebhookID call, got %d", len(mockStore.UpdateWebhookIDCalls))
	}

	if mockStore.UpdateWebhookIDCalls[0].WebhookID != 12345 {
		t.Errorf("Expected webhook ID 12345 stored, got %d", mockStore.UpdateWebhookIDCalls[0].WebhookID)
	}
}

func TestInstallWebhook_CreateWebhookAPIError(t *testing.T) {
	mockClient := newMockGitHubClient()
	mockClient.GetRepoFunc = func(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error) {
		return &GitHubRepoInfo{ID: 98765}, nil
	}
	mockClient.CreateWebhookFunc = func(ctx context.Context, owner, repo string, config GitHubWebhookConfig) (*GitHubWebhook, error) {
		return nil, ErrWebhookCreationFailed
	}

	factory := newMockClientFactory(mockClient)
	service := NewWebhookService(factory, nil)

	result, err := service.InstallWebhook(context.Background(), "test-token", RepoInstallRequest{
		RepositoryID: "repo-123",
		Owner:        "owner",
		Repo:         "repo",
		WebhookURL:   "https://example.com/webhook",
		WebhookSecret: "secret",
	})

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if result.Success {
		t.Error("Expected success to be false")
	}

	if !errors.Is(err, ErrWebhookCreationFailed) {
		t.Errorf("Expected ErrWebhookCreationFailed, got: %v", err)
	}
}

func TestInstallWebhook_RepoNotFound(t *testing.T) {
	mockClient := newMockGitHubClient()
	mockClient.GetRepoFunc = func(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error) {
		return nil, ErrGitHubNotFound
	}

	factory := newMockClientFactory(mockClient)
	service := NewWebhookService(factory, nil)

	result, err := service.InstallWebhook(context.Background(), "test-token", RepoInstallRequest{
		RepositoryID: "repo-123",
		Owner:        "owner",
		Repo:         "nonexistent",
		WebhookURL:   "https://example.com/webhook",
		WebhookSecret: "secret",
	})

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if result.Success {
		t.Error("Expected success to be false")
	}

	if !errors.Is(err, ErrRepositoryNotFound) {
		t.Errorf("Expected ErrRepositoryNotFound, got: %v", err)
	}
}

func TestInstallWebhook_InsufficientPermissions(t *testing.T) {
	mockClient := newMockGitHubClient()
	mockClient.GetRepoFunc = func(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error) {
		return &GitHubRepoInfo{ID: 98765}, nil
	}
	mockClient.CreateWebhookFunc = func(ctx context.Context, owner, repo string, config GitHubWebhookConfig) (*GitHubWebhook, error) {
		return nil, ErrGitHubForbidden
	}

	factory := newMockClientFactory(mockClient)
	service := NewWebhookService(factory, nil)

	result, err := service.InstallWebhook(context.Background(), "test-token", RepoInstallRequest{
		RepositoryID: "repo-123",
		Owner:        "owner",
		Repo:         "repo",
		WebhookURL:   "https://example.com/webhook",
		WebhookSecret: "secret",
	})

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if result.Success {
		t.Error("Expected success to be false")
	}

	if !errors.Is(err, ErrInsufficientPermissions) {
		t.Errorf("Expected ErrInsufficientPermissions, got: %v", err)
	}
}

func TestInstallWebhook_CleanupOnDatabaseFailure(t *testing.T) {
	mockClient := newMockGitHubClient()
	mockClient.GetRepoFunc = func(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error) {
		return &GitHubRepoInfo{ID: 98765}, nil
	}
	mockClient.CreateWebhookFunc = func(ctx context.Context, owner, repo string, config GitHubWebhookConfig) (*GitHubWebhook, error) {
		return &GitHubWebhook{ID: 12345, Active: true}, nil
	}

	mockStore := newMockMetadataStore()
	mockStore.UpdateWebhookIDFunc = func(ctx context.Context, repoID string, webhookID int64) error {
		return errors.New("database error")
	}

	factory := newMockClientFactory(mockClient)
	service := NewWebhookService(factory, mockStore)

	result, err := service.InstallWebhook(context.Background(), "test-token", RepoInstallRequest{
		RepositoryID:  "repo-123",
		Owner:         "owner",
		Repo:          "repo",
		WebhookURL:    "https://example.com/webhook",
		WebhookSecret: "secret",
	})

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if result.Success {
		t.Error("Expected success to be false")
	}

	// Verify cleanup was attempted
	if len(mockClient.DeleteWebhookCalls) != 1 {
		t.Errorf("Expected 1 DeleteWebhook call for cleanup, got %d", len(mockClient.DeleteWebhookCalls))
	}

	if mockClient.DeleteWebhookCalls[0].WebhookID != 12345 {
		t.Errorf("Expected cleanup of webhook 12345, got %d", mockClient.DeleteWebhookCalls[0].WebhookID)
	}
}

func TestInstallWebhook_WebhookAlreadyExists(t *testing.T) {
	mockClient := newMockGitHubClient()
	mockClient.GetRepoFunc = func(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error) {
		return &GitHubRepoInfo{ID: 98765}, nil
	}
	mockClient.CreateWebhookFunc = func(ctx context.Context, owner, repo string, config GitHubWebhookConfig) (*GitHubWebhook, error) {
		return nil, ErrGitHubWebhookExists
	}

	factory := newMockClientFactory(mockClient)
	service := NewWebhookService(factory, nil)

	result, err := service.InstallWebhook(context.Background(), "test-token", RepoInstallRequest{
		RepositoryID: "repo-123",
		Owner:        "owner",
		Repo:         "repo",
		WebhookURL:   "https://example.com/webhook",
		WebhookSecret: "secret",
	})

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if result.Success {
		t.Error("Expected success to be false")
	}

	if !errors.Is(err, ErrGitHubWebhookExists) {
		t.Errorf("Expected ErrWebhookAlreadyExists, got: %v", err)
	}
}

// =============================================================================
// Tests for InstallWebhooksForRepos (Batch)
// =============================================================================

func TestInstallWebhooksForRepos_PartialSuccess(t *testing.T) {
	callCount := 0
	mockClient := newMockGitHubClient()
	mockClient.GetRepoFunc = func(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error) {
		return &GitHubRepoInfo{ID: 98765}, nil
	}
	mockClient.CreateWebhookFunc = func(ctx context.Context, owner, repo string, config GitHubWebhookConfig) (*GitHubWebhook, error) {
		callCount++
		if callCount == 1 {
			return &GitHubWebhook{ID: 111, Active: true}, nil
		}
		return nil, ErrWebhookCreationFailed
	}

	factory := newMockClientFactory(mockClient)
	service := NewWebhookService(factory, nil)

	requests := []RepoInstallRequest{
		{RepositoryID: "repo-1", Owner: "owner", Repo: "repo1", WebhookURL: "url1", WebhookSecret: "secret1"},
		{RepositoryID: "repo-2", Owner: "owner", Repo: "repo2", WebhookURL: "url2", WebhookSecret: "secret2"},
	}

	results := service.InstallWebhooksForRepos(context.Background(), "test-token", requests)

	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}

	if !results[0].Success {
		t.Error("Expected first result to succeed")
	}

	if results[1].Success {
		t.Error("Expected second result to fail")
	}
}

func TestInstallWebhooksForRepos_AllSucceed(t *testing.T) {
	webhookID := int64(100)
	mockClient := newMockGitHubClient()
	mockClient.GetRepoFunc = func(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error) {
		return &GitHubRepoInfo{ID: 98765}, nil
	}
	mockClient.CreateWebhookFunc = func(ctx context.Context, owner, repo string, config GitHubWebhookConfig) (*GitHubWebhook, error) {
		webhookID++
		return &GitHubWebhook{ID: webhookID, Active: true}, nil
	}

	factory := newMockClientFactory(mockClient)
	service := NewWebhookService(factory, nil)

	requests := []RepoInstallRequest{
		{RepositoryID: "repo-1", Owner: "owner", Repo: "repo1", WebhookURL: "url1", WebhookSecret: "secret1"},
		{RepositoryID: "repo-2", Owner: "owner", Repo: "repo2", WebhookURL: "url2", WebhookSecret: "secret2"},
	}

	results := service.InstallWebhooksForRepos(context.Background(), "test-token", requests)

	for i, result := range results {
		if !result.Success {
			t.Errorf("Expected result %d to succeed", i)
		}
	}
}

func TestInstallWebhooksForRepos_AllFail(t *testing.T) {
	mockClient := newMockGitHubClient()
	mockClient.GetRepoFunc = func(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error) {
		return nil, ErrGitHubNotFound
	}

	factory := newMockClientFactory(mockClient)
	service := NewWebhookService(factory, nil)

	requests := []RepoInstallRequest{
		{RepositoryID: "repo-1", Owner: "owner", Repo: "repo1", WebhookURL: "url1", WebhookSecret: "secret1"},
		{RepositoryID: "repo-2", Owner: "owner", Repo: "repo2", WebhookURL: "url2", WebhookSecret: "secret2"},
	}

	results := service.InstallWebhooksForRepos(context.Background(), "test-token", requests)

	for i, result := range results {
		if result.Success {
			t.Errorf("Expected result %d to fail", i)
		}
	}
}

// =============================================================================
// Tests for UninstallWebhook
// =============================================================================

func TestUninstallWebhook_Success(t *testing.T) {
	mockClient := newMockGitHubClient()
	mockStore := newMockMetadataStore()

	factory := newMockClientFactory(mockClient)
	service := NewWebhookService(factory, mockStore)

	err := service.UninstallWebhook(context.Background(), "test-token", "owner", "repo", 12345, "repo-uuid-123")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify DeleteWebhook was called
	if len(mockClient.DeleteWebhookCalls) != 1 {
		t.Errorf("Expected 1 DeleteWebhook call, got %d", len(mockClient.DeleteWebhookCalls))
	}

	// Verify ClearWebhookID was called
	if len(mockStore.ClearWebhookIDCalls) != 1 {
		t.Errorf("Expected 1 ClearWebhookID call, got %d", len(mockStore.ClearWebhookIDCalls))
	}
}

func TestUninstallWebhook_WebhookNotFound(t *testing.T) {
	mockClient := newMockGitHubClient()
	mockClient.DeleteWebhookFunc = func(ctx context.Context, owner, repo string, webhookID int64) error {
		return ErrGitHubNotFound
	}
	mockStore := newMockMetadataStore()

	factory := newMockClientFactory(mockClient)
	service := NewWebhookService(factory, mockStore)

	// Should not error - webhook already gone is OK
	err := service.UninstallWebhook(context.Background(), "test-token", "owner", "repo", 12345, "repo-uuid-123")

	if err != nil {
		t.Fatalf("Expected no error for already-deleted webhook, got: %v", err)
	}

	// Should still clear the local record
	if len(mockStore.ClearWebhookIDCalls) != 1 {
		t.Errorf("Expected 1 ClearWebhookID call, got %d", len(mockStore.ClearWebhookIDCalls))
	}
}

// =============================================================================
// Tests for ParseGitHubURL
// =============================================================================

func TestParseGitHubURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{
			name:      "standard URL",
			url:       "https://github.com/michaellady/roxas",
			wantOwner: "michaellady",
			wantRepo:  "roxas",
			wantErr:   false,
		},
		{
			name:      "URL with .git suffix",
			url:       "https://github.com/michaellady/roxas.git",
			wantOwner: "michaellady",
			wantRepo:  "roxas",
			wantErr:   false,
		},
		{
			name:      "URL with trailing slash",
			url:       "https://github.com/owner/repo/",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantErr:   false,
		},
		{
			name:    "invalid - no owner",
			url:     "https://github.com/",
			wantErr: true,
		},
		{
			name:    "invalid - no repo",
			url:     "https://github.com/owner",
			wantErr: true,
		},
		{
			name:    "invalid - wrong domain",
			url:     "https://gitlab.com/owner/repo",
			wantErr: true,
		},
		{
			name:    "invalid - http",
			url:     "http://github.com/owner/repo",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := ParseGitHubURL(tt.url)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if owner != tt.wantOwner {
				t.Errorf("Owner = %q, want %q", owner, tt.wantOwner)
			}

			if repo != tt.wantRepo {
				t.Errorf("Repo = %q, want %q", repo, tt.wantRepo)
			}
		})
	}
}

// =============================================================================
// Tests for Webhook Configuration
// =============================================================================

func TestWebhookConfig_CorrectEvents(t *testing.T) {
	mockClient := newMockGitHubClient()

	var capturedConfig GitHubWebhookConfig
	mockClient.GetRepoFunc = func(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error) {
		return &GitHubRepoInfo{ID: 98765}, nil
	}
	mockClient.CreateWebhookFunc = func(ctx context.Context, owner, repo string, config GitHubWebhookConfig) (*GitHubWebhook, error) {
		capturedConfig = config
		return &GitHubWebhook{ID: 12345, Active: true}, nil
	}

	factory := newMockClientFactory(mockClient)
	service := NewWebhookService(factory, nil)

	service.InstallWebhook(context.Background(), "test-token", RepoInstallRequest{
		RepositoryID:  "repo-123",
		Owner:         "owner",
		Repo:          "repo",
		WebhookURL:    "https://api.roxas.dev/webhook/123",
		WebhookSecret: "secret",
	})

	if capturedConfig.ContentType != "json" {
		t.Errorf("Expected ContentType json, got %s", capturedConfig.ContentType)
	}

	if len(capturedConfig.Events) != 1 || capturedConfig.Events[0] != "push" {
		t.Errorf("Expected Events [push], got %v", capturedConfig.Events)
	}
}

func TestWebhookConfig_UsesCorrectSecret(t *testing.T) {
	mockClient := newMockGitHubClient()

	var capturedSecret string
	mockClient.GetRepoFunc = func(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error) {
		return &GitHubRepoInfo{ID: 98765}, nil
	}
	mockClient.CreateWebhookFunc = func(ctx context.Context, owner, repo string, config GitHubWebhookConfig) (*GitHubWebhook, error) {
		capturedSecret = config.Secret
		return &GitHubWebhook{ID: 12345, Active: true}, nil
	}

	factory := newMockClientFactory(mockClient)
	service := NewWebhookService(factory, nil)

	expectedSecret := "my-unique-webhook-secret-12345"
	service.InstallWebhook(context.Background(), "test-token", RepoInstallRequest{
		RepositoryID:  "repo-123",
		Owner:         "owner",
		Repo:          "repo",
		WebhookURL:    "https://api.roxas.dev/webhook/123",
		WebhookSecret: expectedSecret,
	})

	if capturedSecret != expectedSecret {
		t.Errorf("Expected secret %s, got %s", expectedSecret, capturedSecret)
	}
}
