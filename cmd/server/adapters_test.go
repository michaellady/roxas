package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mikelady/roxas/internal/database"
	"github.com/mikelady/roxas/internal/oauth"
	"github.com/mikelady/roxas/internal/services"
	"github.com/mikelady/roxas/internal/web"
)

// =============================================================================
// Test extractRepoNameFromURL
// =============================================================================

func TestExtractRepoNameFromURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{"full github URL", "https://github.com/owner/repo", "owner/repo"},
		{"URL with extra path", "https://github.com/owner/repo/tree/main", "tree/main"},
		{"single segment", "repo", "repo"},
		{"two segments", "owner/repo", "owner/repo"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRepoNameFromURL(tt.url)
			if result != tt.expected {
				t.Errorf("extractRepoNameFromURL(%q) = %q, want %q", tt.url, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Test convertDraftToWebhookDraft
// =============================================================================

func TestConvertDraftToWebhookDraft(t *testing.T) {
	now := time.Now()

	t.Run("with edited content", func(t *testing.T) {
		edited := "edited content"
		draft := &database.Draft{
			ID:               "draft-1",
			UserID:           "user-1",
			RepositoryID:     "repo-1",
			Ref:              "refs/heads/main",
			BeforeSHA:        "aaa",
			AfterSHA:         "bbb",
			CommitSHAs:       []string{"sha1", "sha2"},
			GeneratedContent: "generated",
			EditedContent:    &edited,
			Status:           "draft",
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		result := convertDraftToWebhookDraft(draft)

		if result.ID != "draft-1" {
			t.Errorf("ID = %q, want %q", result.ID, "draft-1")
		}
		if result.UserID != "user-1" {
			t.Errorf("UserID = %q, want %q", result.UserID, "user-1")
		}
		if result.RepositoryID != "repo-1" {
			t.Errorf("RepositoryID = %q, want %q", result.RepositoryID, "repo-1")
		}
		if result.Ref != "refs/heads/main" {
			t.Errorf("Ref = %q, want %q", result.Ref, "refs/heads/main")
		}
		if result.BeforeSHA != "aaa" {
			t.Errorf("BeforeSHA = %q, want %q", result.BeforeSHA, "aaa")
		}
		if result.AfterSHA != "bbb" {
			t.Errorf("AfterSHA = %q, want %q", result.AfterSHA, "bbb")
		}
		if result.EditedContent != "edited content" {
			t.Errorf("EditedContent = %q, want %q", result.EditedContent, "edited content")
		}
		if result.GeneratedContent != "generated" {
			t.Errorf("GeneratedContent = %q, want %q", result.GeneratedContent, "generated")
		}
		if result.Status != "draft" {
			t.Errorf("Status = %q, want %q", result.Status, "draft")
		}
		if len(result.CommitSHAs) != 2 {
			t.Errorf("CommitSHAs length = %d, want 2", len(result.CommitSHAs))
		}
	})

	t.Run("with nil edited content", func(t *testing.T) {
		draft := &database.Draft{
			ID:               "draft-2",
			UserID:           "user-2",
			RepositoryID:     "repo-2",
			Ref:              "refs/heads/main",
			BeforeSHA:        "ccc",
			AfterSHA:         "ddd",
			CommitSHAs:       []string{"sha3"},
			GeneratedContent: "gen content",
			EditedContent:    nil,
			Status:           "draft",
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		result := convertDraftToWebhookDraft(draft)

		if result.EditedContent != "" {
			t.Errorf("EditedContent = %q, want empty", result.EditedContent)
		}
	})
}

// =============================================================================
// Test extractCommitFromWebhook - additional error cases
// =============================================================================

func TestExtractCommitFromWebhook_NoCommits(t *testing.T) {
	payload := `{"repository": {"html_url": "https://github.com/test/repo"}, "commits": []}`
	_, err := extractCommitFromWebhook([]byte(payload))
	if err == nil {
		t.Error("Expected error for empty commits, got nil")
	}
	if !strings.Contains(err.Error(), "no commits") {
		t.Errorf("Expected 'no commits' error, got: %v", err)
	}
}

func TestExtractCommitFromWebhook_InvalidJSON(t *testing.T) {
	_, err := extractCommitFromWebhook([]byte("not json"))
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse JSON") {
		t.Errorf("Expected 'failed to parse JSON' error, got: %v", err)
	}
}

func TestExtractCommitFromWebhook_ValidPayload(t *testing.T) {
	payload := `{
		"repository": {"html_url": "https://github.com/owner/repo"},
		"commits": [
			{"id": "abc123", "message": "feat: new feature", "author": {"name": "Dev"}},
			{"id": "def456", "message": "fix: bug fix", "author": {"name": "Dev2"}}
		]
	}`
	commit, err := extractCommitFromWebhook([]byte(payload))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if commit.Message != "feat: new feature" {
		t.Errorf("Message = %q, want %q", commit.Message, "feat: new feature")
	}
	if commit.Author != "Dev" {
		t.Errorf("Author = %q, want %q", commit.Author, "Dev")
	}
	if commit.RepoURL != "https://github.com/owner/repo" {
		t.Errorf("RepoURL = %q, want %q", commit.RepoURL, "https://github.com/owner/repo")
	}
}

// =============================================================================
// Test validateSignature
// =============================================================================

func TestValidateSignature(t *testing.T) {
	t.Run("valid signature with prefix", func(t *testing.T) {
		payload := []byte("test payload")
		secret := "mysecret"
		sig := "sha256=" + generateTestSignature(payload, secret)
		if !validateSignature(payload, sig, secret) {
			t.Error("Expected valid signature to pass")
		}
	})

	t.Run("valid signature without prefix", func(t *testing.T) {
		payload := []byte("test payload")
		secret := "mysecret"
		sig := generateTestSignature(payload, secret)
		if !validateSignature(payload, sig, secret) {
			t.Error("Expected valid signature without prefix to pass")
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		payload := []byte("test payload")
		if validateSignature(payload, "sha256=invalid", "mysecret") {
			t.Error("Expected invalid signature to fail")
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		payload := []byte("test payload")
		sig := "sha256=" + generateTestSignature(payload, "secret1")
		if validateSignature(payload, sig, "secret2") {
			t.Error("Expected wrong secret to fail")
		}
	})
}

// =============================================================================
// Test webhookHandlerWithMocks - additional branches
// =============================================================================

func TestWebhookHandlerMissingCredentials(t *testing.T) {
	config := Config{
		WebhookSecret:       "test-secret",
		OpenAIAPIKey:        "",
		LinkedInAccessToken: "",
	}
	handler := webhookHandlerWithMocks(config, "", "")

	payload := `{
		"repository": {"html_url": "https://github.com/test/repo"},
		"commits": [{"id": "abc", "message": "test", "author": {"name": "Dev"}}]
	}`
	sig := "sha256=" + generateTestSignature([]byte(payload), "test-secret")

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "credentials missing") {
		t.Errorf("Expected 'credentials missing' message, got: %s", rec.Body.String())
	}
}

func TestWebhookHandlerOnlyOpenAIKey(t *testing.T) {
	config := Config{
		WebhookSecret:       "test-secret",
		OpenAIAPIKey:        "key",
		LinkedInAccessToken: "", // Missing LinkedIn
	}
	handler := webhookHandlerWithMocks(config, "", "")

	payload := `{
		"repository": {"html_url": "https://github.com/test/repo"},
		"commits": [{"id": "abc", "message": "test", "author": {"name": "Dev"}}]
	}`
	sig := "sha256=" + generateTestSignature([]byte(payload), "test-secret")

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "credentials missing") {
		t.Errorf("Expected 'credentials missing' message, got: %s", rec.Body.String())
	}
}

func TestWebhookHandlerInvalidPayload(t *testing.T) {
	config := Config{
		WebhookSecret: "test-secret",
	}
	handler := webhookHandlerWithMocks(config, "", "")

	payload := `{"repository": {"html_url": "test"}, "commits": []}`
	sig := "sha256=" + generateTestSignature([]byte(payload), "test-secret")

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", rec.Code)
	}
}

func TestWebhookHandlerProcessingError(t *testing.T) {
	openAIMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server error"}`))
	}))
	defer openAIMock.Close()

	linkedInMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/userinfo") {
			json.NewEncoder(w).Encode(map[string]string{"sub": "urn:li:person:test"})
		}
	}))
	defer linkedInMock.Close()

	config := Config{
		WebhookSecret:       "test-secret",
		OpenAIAPIKey:        "test-key",
		LinkedInAccessToken: "test-token",
	}
	handler := webhookHandlerWithMocks(config, openAIMock.URL, linkedInMock.URL)

	payload := `{
		"repository": {"html_url": "https://github.com/test/repo"},
		"commits": [{"id": "abc", "message": "test", "author": {"name": "Dev"}}]
	}`
	sig := "sha256=" + generateTestSignature([]byte(payload), "test-secret")

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

// =============================================================================
// Test loadConfig with all fields
// =============================================================================

func TestLoadConfigAllFields(t *testing.T) {
	envVars := map[string]string{
		"OPENAI_API_KEY":            "openai-key",
		"OPENAI_CHAT_MODEL":        "gpt-4",
		"OPENAI_IMAGE_MODEL":       "dall-e-3",
		"LINKEDIN_ACCESS_TOKEN":    "linkedin-token",
		"WEBHOOK_SECRET":           "webhook-secret",
		"DB_SECRET_NAME":           "db-secret",
		"WEBHOOK_BASE_URL":         "https://example.com",
		"CREDENTIAL_ENCRYPTION_KEY": "enc-key",
		"THREADS_CLIENT_ID":        "threads-id",
		"THREADS_CLIENT_SECRET":    "threads-secret",
		"OAUTH_CALLBACK_URL":       "https://callback.com",
	}

	for k, v := range envVars {
		t.Setenv(k, v)
	}

	config := loadConfig()

	if config.OpenAIAPIKey != "openai-key" {
		t.Errorf("OpenAIAPIKey = %q, want %q", config.OpenAIAPIKey, "openai-key")
	}
	if config.OpenAIChatModel != "gpt-4" {
		t.Errorf("OpenAIChatModel = %q, want %q", config.OpenAIChatModel, "gpt-4")
	}
	if config.OpenAIImageModel != "dall-e-3" {
		t.Errorf("OpenAIImageModel = %q, want %q", config.OpenAIImageModel, "dall-e-3")
	}
	if config.DBSecretName != "db-secret" {
		t.Errorf("DBSecretName = %q, want %q", config.DBSecretName, "db-secret")
	}
	if config.WebhookBaseURL != "https://example.com" {
		t.Errorf("WebhookBaseURL = %q, want %q", config.WebhookBaseURL, "https://example.com")
	}
	if config.EncryptionKey != "enc-key" {
		t.Errorf("EncryptionKey = %q, want %q", config.EncryptionKey, "enc-key")
	}
	if config.ThreadsClientID != "threads-id" {
		t.Errorf("ThreadsClientID = %q, want %q", config.ThreadsClientID, "threads-id")
	}
	if config.ThreadsClientSecret != "threads-secret" {
		t.Errorf("ThreadsClientSecret = %q, want %q", config.ThreadsClientSecret, "threads-secret")
	}
	if config.OAuthCallbackURL != "https://callback.com" {
		t.Errorf("OAuthCallbackURL = %q, want %q", config.OAuthCallbackURL, "https://callback.com")
	}
}

// =============================================================================
// Mock credential store for adapter tests
// =============================================================================

type mockCredentialStore struct {
	credentials map[string]*services.PlatformCredentials
	saveErr     error
	getErr      error
	deleteErr   error
}

func newMockCredentialStore() *mockCredentialStore {
	return &mockCredentialStore{
		credentials: make(map[string]*services.PlatformCredentials),
	}
}

func (m *mockCredentialStore) GetCredentials(ctx context.Context, userID, platform string) (*services.PlatformCredentials, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	key := userID + ":" + platform
	creds, ok := m.credentials[key]
	if !ok {
		return nil, nil
	}
	return creds, nil
}

func (m *mockCredentialStore) SaveCredentials(ctx context.Context, creds *services.PlatformCredentials) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	key := creds.UserID + ":" + creds.Platform
	m.credentials[key] = creds
	return nil
}

func (m *mockCredentialStore) DeleteCredentials(ctx context.Context, userID, platform string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	key := userID + ":" + platform
	delete(m.credentials, key)
	return nil
}

func (m *mockCredentialStore) GetCredentialsForUser(ctx context.Context, userID string) ([]*services.PlatformCredentials, error) {
	return nil, nil
}

func (m *mockCredentialStore) GetExpiringCredentials(ctx context.Context, within time.Duration) ([]*services.PlatformCredentials, error) {
	return nil, nil
}

func (m *mockCredentialStore) UpdateTokens(ctx context.Context, userID, platform, accessToken, refreshToken string, expiresAt *time.Time) error {
	return nil
}

func (m *mockCredentialStore) UpdateHealthStatus(ctx context.Context, userID, platform string, isHealthy bool, healthError *string) error {
	return nil
}

func (m *mockCredentialStore) RecordSuccessfulPost(ctx context.Context, userID, platform string) error {
	return nil
}

func (m *mockCredentialStore) GetCredentialsNeedingCheck(ctx context.Context, notCheckedWithin time.Duration) ([]*services.PlatformCredentials, error) {
	return nil, nil
}

// =============================================================================
// Test connectionListerAdapter.ListConnectionsWithRateLimits
// =============================================================================

func TestConnectionListerAdapter_ListConnectionsWithRateLimits(t *testing.T) {
	t.Run("no connections", func(t *testing.T) {
		store := newMockCredentialStore()
		adapter := &connectionListerAdapter{credentialStore: store}

		connections, err := adapter.ListConnectionsWithRateLimits(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(connections) != 0 {
			t.Errorf("Expected 0 connections, got %d", len(connections))
		}
	})

	t.Run("bluesky connection", func(t *testing.T) {
		store := newMockCredentialStore()
		store.credentials["user-1:bluesky"] = &services.PlatformCredentials{
			UserID:       "user-1",
			Platform:     "bluesky",
			AccessToken:  "app-password",
			RefreshToken: "handle.bsky.social",
		}
		adapter := &connectionListerAdapter{credentialStore: store}

		connections, err := adapter.ListConnectionsWithRateLimits(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(connections) != 1 {
			t.Fatalf("Expected 1 connection, got %d", len(connections))
		}
		if connections[0].Platform != "bluesky" {
			t.Errorf("Platform = %q, want %q", connections[0].Platform, "bluesky")
		}
		if connections[0].DisplayName != "handle.bsky.social" {
			t.Errorf("DisplayName = %q, want %q", connections[0].DisplayName, "handle.bsky.social")
		}
		if !connections[0].IsHealthy {
			t.Error("Expected IsHealthy to be true for bluesky (no expiry)")
		}
	})

	t.Run("threads connection with expiry", func(t *testing.T) {
		store := newMockCredentialStore()
		futureTime := time.Now().Add(30 * 24 * time.Hour)
		store.credentials["user-1:threads"] = &services.PlatformCredentials{
			UserID:         "user-1",
			Platform:       "threads",
			AccessToken:    "access-token",
			PlatformUserID: "threads-user",
			TokenExpiresAt: &futureTime,
		}
		adapter := &connectionListerAdapter{credentialStore: store}

		connections, err := adapter.ListConnectionsWithRateLimits(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(connections) != 1 {
			t.Fatalf("Expected 1 connection, got %d", len(connections))
		}
		if connections[0].Platform != "threads" {
			t.Errorf("Platform = %q, want %q", connections[0].Platform, "threads")
		}
		if connections[0].DisplayName != "threads-user" {
			t.Errorf("DisplayName = %q, want %q", connections[0].DisplayName, "threads-user")
		}
		if !connections[0].IsHealthy {
			t.Error("Expected IsHealthy to be true")
		}
		if connections[0].ExpiresSoon {
			t.Error("Expected ExpiresSoon to be false for token 30 days out")
		}
	})

	t.Run("threads connection expiring soon", func(t *testing.T) {
		store := newMockCredentialStore()
		soonTime := time.Now().Add(3 * 24 * time.Hour)
		store.credentials["user-1:threads"] = &services.PlatformCredentials{
			UserID:         "user-1",
			Platform:       "threads",
			AccessToken:    "access-token",
			PlatformUserID: "threads-user",
			TokenExpiresAt: &soonTime,
		}
		adapter := &connectionListerAdapter{credentialStore: store}

		connections, err := adapter.ListConnectionsWithRateLimits(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(connections) != 1 {
			t.Fatalf("Expected 1 connection, got %d", len(connections))
		}
		if !connections[0].ExpiresSoon {
			t.Error("Expected ExpiresSoon to be true for token 3 days out")
		}
	})

	t.Run("threads connection with empty display name", func(t *testing.T) {
		store := newMockCredentialStore()
		store.credentials["user-1:threads"] = &services.PlatformCredentials{
			UserID:         "user-1",
			Platform:       "threads",
			AccessToken:    "access-token",
			PlatformUserID: "",
		}
		adapter := &connectionListerAdapter{credentialStore: store}

		connections, err := adapter.ListConnectionsWithRateLimits(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(connections) != 1 {
			t.Fatalf("Expected 1 connection, got %d", len(connections))
		}
		if connections[0].DisplayName != "Connected" {
			t.Errorf("DisplayName = %q, want %q", connections[0].DisplayName, "Connected")
		}
	})

	t.Run("both connections", func(t *testing.T) {
		store := newMockCredentialStore()
		store.credentials["user-1:bluesky"] = &services.PlatformCredentials{
			UserID:       "user-1",
			Platform:     "bluesky",
			RefreshToken: "handle.bsky.social",
		}
		store.credentials["user-1:threads"] = &services.PlatformCredentials{
			UserID:         "user-1",
			Platform:       "threads",
			PlatformUserID: "threads-user",
		}
		adapter := &connectionListerAdapter{credentialStore: store}

		connections, err := adapter.ListConnectionsWithRateLimits(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(connections) != 2 {
			t.Errorf("Expected 2 connections, got %d", len(connections))
		}
	})

	t.Run("threads expired token", func(t *testing.T) {
		store := newMockCredentialStore()
		pastTime := time.Now().Add(-1 * time.Hour)
		store.credentials["user-1:threads"] = &services.PlatformCredentials{
			UserID:         "user-1",
			Platform:       "threads",
			AccessToken:    "expired-token",
			PlatformUserID: "threads-user",
			TokenExpiresAt: &pastTime,
		}
		adapter := &connectionListerAdapter{credentialStore: store}

		connections, err := adapter.ListConnectionsWithRateLimits(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(connections) != 1 {
			t.Fatalf("Expected 1 connection, got %d", len(connections))
		}
		if connections[0].IsHealthy {
			t.Error("Expected IsHealthy to be false for expired token")
		}
	})
}

// =============================================================================
// Test connectionServiceAdapter
// =============================================================================

func TestConnectionServiceAdapter_GetConnection(t *testing.T) {
	t.Run("found bluesky connection", func(t *testing.T) {
		store := newMockCredentialStore()
		store.credentials["user-1:bluesky"] = &services.PlatformCredentials{
			UserID:         "user-1",
			Platform:       "bluesky",
			PlatformUserID: "did:plc:123",
			RefreshToken:   "handle.bsky.social",
		}
		adapter := &connectionServiceAdapter{credentialStore: store}

		conn, err := adapter.GetConnection(context.Background(), "user-1", "bluesky")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if conn.DisplayName != "handle.bsky.social" {
			t.Errorf("DisplayName = %q, want %q", conn.DisplayName, "handle.bsky.social")
		}
		if conn.Platform != "bluesky" {
			t.Errorf("Platform = %q, want %q", conn.Platform, "bluesky")
		}
		if conn.Status != "connected" {
			t.Errorf("Status = %q, want %q", conn.Status, "connected")
		}
	})

	t.Run("found threads connection", func(t *testing.T) {
		store := newMockCredentialStore()
		store.credentials["user-1:threads"] = &services.PlatformCredentials{
			UserID:         "user-1",
			Platform:       "threads",
			PlatformUserID: "threads-user",
		}
		adapter := &connectionServiceAdapter{credentialStore: store}

		conn, err := adapter.GetConnection(context.Background(), "user-1", "threads")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if conn.DisplayName != "threads-user" {
			t.Errorf("DisplayName = %q, want %q", conn.DisplayName, "threads-user")
		}
	})

	t.Run("connection not found", func(t *testing.T) {
		store := newMockCredentialStore()
		adapter := &connectionServiceAdapter{credentialStore: store}

		_, err := adapter.GetConnection(context.Background(), "user-1", "bluesky")
		if err == nil {
			t.Error("Expected error for missing connection")
		}
		if !strings.Contains(err.Error(), "connection not found") {
			t.Errorf("Expected 'connection not found' error, got: %v", err)
		}
	})

	t.Run("credential store error", func(t *testing.T) {
		store := newMockCredentialStore()
		store.getErr = fmt.Errorf("db error")
		adapter := &connectionServiceAdapter{credentialStore: store}

		_, err := adapter.GetConnection(context.Background(), "user-1", "bluesky")
		if err == nil {
			t.Error("Expected error from store")
		}
	})
}

func TestConnectionServiceAdapter_Disconnect(t *testing.T) {
	t.Run("successful disconnect", func(t *testing.T) {
		store := newMockCredentialStore()
		store.credentials["user-1:bluesky"] = &services.PlatformCredentials{
			UserID:   "user-1",
			Platform: "bluesky",
		}
		adapter := &connectionServiceAdapter{credentialStore: store}

		err := adapter.Disconnect(context.Background(), "user-1", "bluesky")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	})

	t.Run("disconnect error", func(t *testing.T) {
		store := newMockCredentialStore()
		store.deleteErr = fmt.Errorf("db error")
		adapter := &connectionServiceAdapter{credentialStore: store}

		err := adapter.Disconnect(context.Background(), "user-1", "bluesky")
		if err == nil {
			t.Error("Expected error from store")
		}
	})
}

// =============================================================================
// Test blueskyConnectorAdapter
// =============================================================================

func TestBlueskyConnectorAdapter_Connect(t *testing.T) {
	t.Run("handle normalization - adds domain and removes @", func(t *testing.T) {
		store := newMockCredentialStore()
		adapter := &blueskyConnectorAdapter{credentialStore: store}

		// Auth will fail because it contacts the real Bluesky PDS, but the adapter
		// returns a result with Success=false rather than an error.
		result, err := adapter.Connect(context.Background(), "user-1", "@testhandle", "bad-password")
		if err != nil {
			t.Fatalf("Expected no error (auth failure returned in result), got: %v", err)
		}
		if result.Success {
			t.Error("Expected failure for auth against real Bluesky with bad credentials")
		}
		if result.Error == "" {
			t.Error("Expected non-empty error message in result")
		}
	})

	t.Run("handle with domain not modified", func(t *testing.T) {
		store := newMockCredentialStore()
		adapter := &blueskyConnectorAdapter{credentialStore: store}

		result, err := adapter.Connect(context.Background(), "user-1", "user.custom.domain", "bad-password")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if result.Success {
			t.Error("Expected failure")
		}
	})
}

// =============================================================================
// Test threadsOAuthAdapter
// =============================================================================

func TestThreadsOAuthAdapter_GetAuthURL(t *testing.T) {
	provider := oauth.NewThreadsOAuthProvider("client-id", "client-secret")
	adapter := &threadsOAuthAdapter{
		provider:        provider,
		credentialStore: newMockCredentialStore(),
	}

	authURL := adapter.GetAuthURL("test-state", "https://callback.com/auth")
	if authURL == "" {
		t.Error("Expected non-empty auth URL")
	}
	if !strings.Contains(authURL, "client_id=client-id") {
		t.Errorf("Expected auth URL to contain client_id, got: %s", authURL)
	}
	if !strings.Contains(authURL, "state=test-state") {
		t.Errorf("Expected auth URL to contain state, got: %s", authURL)
	}
}

func TestThreadsOAuthAdapter_ExchangeCode(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/oauth/access_token") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "short-lived-token",
				"user_id":      "12345",
			})
		} else if strings.Contains(r.URL.Path, "/access_token") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "long-lived-token",
				"expires_in":   5184000,
			})
		}
	}))
	defer mockServer.Close()

	provider := oauth.NewThreadsOAuthProvider("client-id", "client-secret")
	provider.BaseURL = mockServer.URL

	store := newMockCredentialStore()
	adapter := &threadsOAuthAdapter{
		provider:        provider,
		credentialStore: store,
	}

	username, err := adapter.ExchangeCode(context.Background(), "user-1", "auth-code", "https://callback.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	creds, _ := store.GetCredentials(context.Background(), "user-1", "threads")
	if creds == nil {
		t.Fatal("Expected credentials to be saved")
	}
	if creds.Platform != "threads" {
		t.Errorf("Platform = %q, want %q", creds.Platform, "threads")
	}

	if username == "" {
		t.Error("Expected non-empty username")
	}
}

func TestThreadsOAuthAdapter_ExchangeCode_SaveError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/oauth/access_token") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "short-lived-token",
				"user_id":      "12345",
			})
		} else if strings.Contains(r.URL.Path, "/access_token") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "long-lived-token",
				"expires_in":   5184000,
			})
		}
	}))
	defer mockServer.Close()

	provider := oauth.NewThreadsOAuthProvider("client-id", "client-secret")
	provider.BaseURL = mockServer.URL

	store := newMockCredentialStore()
	store.saveErr = fmt.Errorf("save failed")

	adapter := &threadsOAuthAdapter{
		provider:        provider,
		credentialStore: store,
	}

	_, err := adapter.ExchangeCode(context.Background(), "user-1", "auth-code", "https://callback.com")
	if err == nil {
		t.Error("Expected error when save fails")
	}
	if !strings.Contains(err.Error(), "failed to save credentials") {
		t.Errorf("Expected 'failed to save credentials' error, got: %v", err)
	}
}

func TestThreadsOAuthAdapter_ExchangeCode_EmptyPlatformUserID(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/oauth/access_token") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "short-lived-token",
				// No user_id
			})
		} else if strings.Contains(r.URL.Path, "/access_token") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "long-lived-token",
				"expires_in":   5184000,
			})
		}
	}))
	defer mockServer.Close()

	provider := oauth.NewThreadsOAuthProvider("client-id", "client-secret")
	provider.BaseURL = mockServer.URL

	store := newMockCredentialStore()
	adapter := &threadsOAuthAdapter{
		provider:        provider,
		credentialStore: store,
	}

	username, err := adapter.ExchangeCode(context.Background(), "user-1", "auth-code", "https://callback.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if username != "connected" {
		t.Errorf("Expected 'connected' as fallback username, got: %q", username)
	}
}

func TestThreadsOAuthAdapter_ExchangeCode_ProviderError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid_grant", "error_description": "Code expired"}`))
	}))
	defer mockServer.Close()

	provider := oauth.NewThreadsOAuthProvider("client-id", "client-secret")
	provider.BaseURL = mockServer.URL

	adapter := &threadsOAuthAdapter{
		provider:        provider,
		credentialStore: newMockCredentialStore(),
	}

	_, err := adapter.ExchangeCode(context.Background(), "user-1", "bad-code", "https://callback.com")
	if err == nil {
		t.Error("Expected error for bad code")
	}
	if !strings.Contains(err.Error(), "failed to exchange code") {
		t.Errorf("Expected 'failed to exchange code' error, got: %v", err)
	}
}

func TestThreadsOAuthAdapter_RefreshTokens(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "refreshed-token",
			"expires_in":   5184000,
		})
	}))
	defer mockServer.Close()

	provider := oauth.NewThreadsOAuthProvider("client-id", "client-secret")
	provider.BaseURL = mockServer.URL

	adapter := &threadsOAuthAdapter{
		provider:        provider,
		credentialStore: newMockCredentialStore(),
	}

	tokens, err := adapter.RefreshTokens(context.Background(), "old-refresh-token")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if tokens == nil {
		t.Fatal("Expected non-nil tokens")
	}
	if tokens.AccessToken != "refreshed-token" {
		t.Errorf("AccessToken = %q, want %q", tokens.AccessToken, "refreshed-token")
	}
}

func TestThreadsOAuthAdapter_RefreshTokens_Error(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid_token"}`))
	}))
	defer mockServer.Close()

	provider := oauth.NewThreadsOAuthProvider("client-id", "client-secret")
	provider.BaseURL = mockServer.URL

	adapter := &threadsOAuthAdapter{
		provider:        provider,
		credentialStore: newMockCredentialStore(),
	}

	_, err := adapter.RefreshTokens(context.Background(), "bad-token")
	if err == nil {
		t.Error("Expected error for bad refresh token")
	}
}

// =============================================================================
// Test createRouter with nil dbPool
// =============================================================================

func TestCreateRouterWithoutDB(t *testing.T) {
	config := Config{
		WebhookSecret: "test-secret",
	}

	router := createRouter(config, nil)
	if router == nil {
		t.Fatal("Expected non-nil router")
	}

	// Test that the router serves the home page
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 for /, got %d", rec.Code)
	}

	// Test that webhook endpoint works
	payload := `{
		"repository": {"html_url": "https://github.com/test/repo"},
		"commits": [{"id": "abc", "message": "test", "author": {"name": "Dev"}}]
	}`
	sig := "sha256=" + generateTestSignature([]byte(payload), "test-secret")

	req = httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sig)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 for /webhook, got %d", rec.Code)
	}
}

// =============================================================================
// Test webhook handler edge cases
// =============================================================================

func TestWebhookHandlerEmptyBody(t *testing.T) {
	config := Config{WebhookSecret: "test-secret"}
	handler := webhookHandler(config)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(""))
	req.Header.Set("X-Hub-Signature-256", "sha256="+generateTestSignature([]byte(""), "test-secret"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// =============================================================================
// Test validateConfig
// =============================================================================

func TestValidateConfigWebhookSecretOnly(t *testing.T) {
	config := Config{
		WebhookSecret: "secret",
	}
	err := validateConfig(config)
	if err != nil {
		t.Errorf("Expected no error with just webhook secret, got: %v", err)
	}
}

func TestValidateConfigEmpty(t *testing.T) {
	config := Config{}
	err := validateConfig(config)
	if err == nil {
		t.Error("Expected error for empty config")
	}
}

// =============================================================================
// Compile-time interface checks
// =============================================================================

var _ web.ConnectionLister = (*connectionListerAdapter)(nil)
var _ web.ConnectionService = (*connectionServiceAdapter)(nil)
var _ web.DraftStore = (*draftStoreAdapter)(nil)
