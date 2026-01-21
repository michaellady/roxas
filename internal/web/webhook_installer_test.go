package web

import (
	"context"
	"errors"
	"testing"

	"github.com/mikelady/roxas/internal/services"
)

// mockGitHubCredentialStore implements GitHubCredentialStore for testing
type mockGitHubCredentialStore struct {
	accessToken string
	err         error
}

func (m *mockGitHubCredentialStore) GetGitHubAccessToken(ctx context.Context, userID string) (string, error) {
	return m.accessToken, m.err
}

// mockWebhookService mocks the WebhookService for testing
type mockWebhookService struct {
	installFunc func(ctx context.Context, accessToken string, req services.RepoInstallRequest) (*services.WebhookInstallResult, error)
}

func (m *mockWebhookService) InstallWebhook(ctx context.Context, accessToken string, req services.RepoInstallRequest) (*services.WebhookInstallResult, error) {
	if m.installFunc != nil {
		return m.installFunc(ctx, accessToken, req)
	}
	return &services.WebhookInstallResult{Success: true, WebhookID: 12345}, nil
}

func TestWebhookInstallerAdapter_Success(t *testing.T) {
	credStore := &mockGitHubCredentialStore{accessToken: "test-token"}

	// Create a mock that wraps the real interface
	mockService := &mockWebhookService{
		installFunc: func(ctx context.Context, accessToken string, req services.RepoInstallRequest) (*services.WebhookInstallResult, error) {
			return &services.WebhookInstallResult{
				RepositoryID: req.RepositoryID,
				GitHubRepoID: 98765,
				WebhookID:    12345,
				Success:      true,
			}, nil
		},
	}

	// Create adapter with real WebhookService that uses the mock factory
	mockClientFactory := &testClientFactory{service: mockService}
	webhookService := services.NewWebhookService(mockClientFactory, nil)

	adapter := NewWebhookInstallerAdapter(webhookService, credStore)

	result, err := adapter.InstallWebhookForRepo(
		context.Background(),
		"user-123",
		"repo-uuid-456",
		"https://github.com/michaellady/roxas",
		"https://api.roxas.dev/webhook/repo-uuid-456",
		"webhook-secret",
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got failure: %s", result.ErrorMessage)
	}

	if result.WebhookID != 12345 {
		t.Errorf("Expected webhook ID 12345, got %d", result.WebhookID)
	}
}

func TestWebhookInstallerAdapter_NoGitHubConnection(t *testing.T) {
	// User doesn't have GitHub connected
	credStore := &mockGitHubCredentialStore{accessToken: ""}

	webhookService := services.NewWebhookService(nil, nil)
	adapter := NewWebhookInstallerAdapter(webhookService, credStore)

	result, err := adapter.InstallWebhookForRepo(
		context.Background(),
		"user-123",
		"repo-uuid-456",
		"https://github.com/owner/repo",
		"https://api.example.com/webhook/repo-uuid-456",
		"secret",
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Success {
		t.Error("Expected failure when GitHub not connected")
	}

	if result.ErrorMessage != "GitHub not connected" {
		t.Errorf("Expected 'GitHub not connected' error, got: %s", result.ErrorMessage)
	}
}

func TestWebhookInstallerAdapter_CredentialStoreError(t *testing.T) {
	// Error retrieving credentials
	credStore := &mockGitHubCredentialStore{err: errors.New("database error")}

	webhookService := services.NewWebhookService(nil, nil)
	adapter := NewWebhookInstallerAdapter(webhookService, credStore)

	result, err := adapter.InstallWebhookForRepo(
		context.Background(),
		"user-123",
		"repo-uuid-456",
		"https://github.com/owner/repo",
		"https://api.example.com/webhook/repo-uuid-456",
		"secret",
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Success {
		t.Error("Expected failure when credential store errors")
	}
}

func TestWebhookInstallerAdapter_InvalidGitHubURL(t *testing.T) {
	credStore := &mockGitHubCredentialStore{accessToken: "test-token"}

	webhookService := services.NewWebhookService(nil, nil)
	adapter := NewWebhookInstallerAdapter(webhookService, credStore)

	result, err := adapter.InstallWebhookForRepo(
		context.Background(),
		"user-123",
		"repo-uuid-456",
		"https://gitlab.com/owner/repo", // Invalid - not GitHub
		"https://api.example.com/webhook/repo-uuid-456",
		"secret",
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Success {
		t.Error("Expected failure for invalid GitHub URL")
	}

	if result.ErrorMessage == "" {
		t.Error("Expected error message for invalid URL")
	}
}

// testClientFactory is a test helper for creating mock webhook services
type testClientFactory struct {
	service *mockWebhookService
}

func (f *testClientFactory) NewClient(accessToken string) services.GitHubWebhookClient {
	return &testGitHubClient{service: f.service}
}

type testGitHubClient struct {
	service *mockWebhookService
}

func (c *testGitHubClient) CreateWebhook(ctx context.Context, owner, repo string, config services.GitHubWebhookConfig) (*services.GitHubWebhook, error) {
	if c.service != nil && c.service.installFunc != nil {
		result, err := c.service.installFunc(ctx, "", services.RepoInstallRequest{
			Owner:         owner,
			Repo:          repo,
			WebhookURL:    config.URL,
			WebhookSecret: config.Secret,
		})
		if err != nil {
			return nil, err
		}
		return &services.GitHubWebhook{ID: result.WebhookID, Active: true}, nil
	}
	return &services.GitHubWebhook{ID: 12345, Active: true}, nil
}

func (c *testGitHubClient) DeleteWebhook(ctx context.Context, owner, repo string, webhookID int64) error {
	return nil
}

func (c *testGitHubClient) GetRepo(ctx context.Context, owner, repo string) (*services.GitHubRepoInfo, error) {
	return &services.GitHubRepoInfo{ID: 98765, FullName: owner + "/" + repo}, nil
}
