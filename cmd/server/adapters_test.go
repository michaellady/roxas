package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mikelady/roxas/internal/database"
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
// Test loadConfig with all fields
// =============================================================================

func TestLoadConfigAllFields(t *testing.T) {
	envVars := map[string]string{
		"WEBHOOK_SECRET":            "webhook-secret",
		"DB_SECRET_NAME":            "db-secret",
		"WEBHOOK_BASE_URL":          "https://example.com",
		"CREDENTIAL_ENCRYPTION_KEY": "enc-key",
		"OAUTH_CALLBACK_URL":        "https://callback.com",
		"BEDROCK_MODEL_ID":          "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
	}

	for k, v := range envVars {
		t.Setenv(k, v)
	}

	config := loadConfig()

	if config.DBSecretName != "db-secret" {
		t.Errorf("DBSecretName = %q, want %q", config.DBSecretName, "db-secret")
	}
	if config.WebhookBaseURL != "https://example.com" {
		t.Errorf("WebhookBaseURL = %q, want %q", config.WebhookBaseURL, "https://example.com")
	}
	if config.EncryptionKey != "enc-key" {
		t.Errorf("EncryptionKey = %q, want %q", config.EncryptionKey, "enc-key")
	}
	if config.OAuthCallbackURL != "https://callback.com" {
		t.Errorf("OAuthCallbackURL = %q, want %q", config.OAuthCallbackURL, "https://callback.com")
	}
	if config.BedrockModelID != "us.anthropic.claude-sonnet-4-5-20250929-v1:0" {
		t.Errorf("BedrockModelID = %q, want %q", config.BedrockModelID, "us.anthropic.claude-sonnet-4-5-20250929-v1:0")
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

	t.Run("buffer connection", func(t *testing.T) {
		store := newMockCredentialStore()
		store.credentials["user-1:buffer"] = &services.PlatformCredentials{
			UserID:         "user-1",
			Platform:       "buffer",
			AccessToken:    "buffer-token",
			PlatformUserID: "twitter:@testuser, linkedin:Test Co",
		}
		adapter := &connectionListerAdapter{credentialStore: store}

		connections, err := adapter.ListConnectionsWithRateLimits(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(connections) != 1 {
			t.Fatalf("Expected 1 connection, got %d", len(connections))
		}
		if connections[0].Platform != "buffer" {
			t.Errorf("Platform = %q, want %q", connections[0].Platform, "buffer")
		}
		if connections[0].DisplayName != "twitter:@testuser, linkedin:Test Co" {
			t.Errorf("DisplayName = %q, want %q", connections[0].DisplayName, "twitter:@testuser, linkedin:Test Co")
		}
		if !connections[0].IsHealthy {
			t.Error("Expected IsHealthy to be true for buffer")
		}
	})

	t.Run("buffer connection with empty display name", func(t *testing.T) {
		store := newMockCredentialStore()
		store.credentials["user-1:buffer"] = &services.PlatformCredentials{
			UserID:         "user-1",
			Platform:       "buffer",
			AccessToken:    "buffer-token",
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
}

// =============================================================================
// Test connectionServiceAdapter
// =============================================================================

func TestConnectionServiceAdapter_GetConnection(t *testing.T) {
	t.Run("found buffer connection", func(t *testing.T) {
		store := newMockCredentialStore()
		store.credentials["user-1:buffer"] = &services.PlatformCredentials{
			UserID:         "user-1",
			Platform:       "buffer",
			PlatformUserID: "twitter:@testuser, linkedin:Test Co",
		}
		adapter := &connectionServiceAdapter{credentialStore: store}

		conn, err := adapter.GetConnection(context.Background(), "user-1", "buffer")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if conn.DisplayName != "twitter:@testuser, linkedin:Test Co" {
			t.Errorf("DisplayName = %q, want %q", conn.DisplayName, "twitter:@testuser, linkedin:Test Co")
		}
		if conn.Platform != "buffer" {
			t.Errorf("Platform = %q, want %q", conn.Platform, "buffer")
		}
		if conn.Status != "connected" {
			t.Errorf("Status = %q, want %q", conn.Status, "connected")
		}
	})

	t.Run("connection not found", func(t *testing.T) {
		store := newMockCredentialStore()
		adapter := &connectionServiceAdapter{credentialStore: store}

		_, err := adapter.GetConnection(context.Background(), "user-1", "buffer")
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

		_, err := adapter.GetConnection(context.Background(), "user-1", "buffer")
		if err == nil {
			t.Error("Expected error from store")
		}
	})
}

func TestConnectionServiceAdapter_Disconnect(t *testing.T) {
	t.Run("successful disconnect", func(t *testing.T) {
		store := newMockCredentialStore()
		store.credentials["user-1:buffer"] = &services.PlatformCredentials{
			UserID:   "user-1",
			Platform: "buffer",
		}
		adapter := &connectionServiceAdapter{credentialStore: store}

		err := adapter.Disconnect(context.Background(), "user-1", "buffer")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	})

	t.Run("disconnect error", func(t *testing.T) {
		store := newMockCredentialStore()
		store.deleteErr = fmt.Errorf("db error")
		adapter := &connectionServiceAdapter{credentialStore: store}

		err := adapter.Disconnect(context.Background(), "user-1", "buffer")
		if err == nil {
			t.Error("Expected error from store")
		}
	})
}

// =============================================================================
// Test bufferConnectorAdapter
// =============================================================================

func TestBufferConnectorAdapter_Connect(t *testing.T) {
	t.Run("valid token stores credentials", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			body, _ := io.ReadAll(r.Body)
			query := string(body)
			if strings.Contains(query, "account") {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"account": map[string]interface{}{
							"organizations": []map[string]interface{}{
								{"id": "org-1"},
							},
						},
					},
				})
			} else if strings.Contains(query, "channels") {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"channels": []map[string]interface{}{
							{"id": "prof-1", "service": "twitter", "formattedUsername": "@testuser"},
							{"id": "prof-2", "service": "linkedin", "formattedUsername": "Test Co"},
						},
					},
				})
			}
		}))
		defer mockServer.Close()

		store := newMockCredentialStore()
		adapter := &bufferConnectorAdapter{credentialStore: store}

		// We need to create a client that uses the mock server
		// The adapter creates its own client, so we test the full flow
		// by setting the BUFFER API to return profiles
		result, err := adapter.connectWithBaseURL(context.Background(), "user-1", "test-token", mockServer.URL)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !result.Success {
			t.Errorf("Expected success, got error: %s", result.Error)
		}
		if len(result.Profiles) != 2 {
			t.Errorf("Expected 2 profiles, got %d", len(result.Profiles))
		}

		creds, _ := store.GetCredentials(context.Background(), "user-1", "buffer")
		if creds == nil {
			t.Fatal("Expected credentials to be saved")
		}
		if creds.AccessToken != "test-token" {
			t.Errorf("AccessToken = %q, want %q", creds.AccessToken, "test-token")
		}
	})

	t.Run("no profiles returns error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			body, _ := io.ReadAll(r.Body)
			query := string(body)
			if strings.Contains(query, "account") {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"account": map[string]interface{}{
							"organizations": []map[string]interface{}{
								{"id": "org-1"},
							},
						},
					},
				})
			} else if strings.Contains(query, "channels") {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"channels": []map[string]interface{}{},
					},
				})
			}
		}))
		defer mockServer.Close()

		store := newMockCredentialStore()
		adapter := &bufferConnectorAdapter{credentialStore: store}

		result, err := adapter.connectWithBaseURL(context.Background(), "user-1", "test-token", mockServer.URL)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Success {
			t.Error("Expected failure for no profiles")
		}
		if !strings.Contains(result.Error, "No profiles") {
			t.Errorf("Expected 'No profiles' error, got: %s", result.Error)
		}
	})

	t.Run("invalid token returns error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Unauthorized"}`))
		}))
		defer mockServer.Close()

		store := newMockCredentialStore()
		adapter := &bufferConnectorAdapter{credentialStore: store}

		result, err := adapter.connectWithBaseURL(context.Background(), "user-1", "bad-token", mockServer.URL)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Success {
			t.Error("Expected failure for bad token")
		}
	})

	t.Run("save error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			body, _ := io.ReadAll(r.Body)
			query := string(body)
			if strings.Contains(query, "account") {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"account": map[string]interface{}{
							"organizations": []map[string]interface{}{
								{"id": "org-1"},
							},
						},
					},
				})
			} else if strings.Contains(query, "channels") {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"channels": []map[string]interface{}{
							{"id": "prof-1", "service": "twitter", "formattedUsername": "@testuser"},
						},
					},
				})
			}
		}))
		defer mockServer.Close()

		store := newMockCredentialStore()
		store.saveErr = fmt.Errorf("save failed")
		adapter := &bufferConnectorAdapter{credentialStore: store}

		_, err := adapter.connectWithBaseURL(context.Background(), "user-1", "test-token", mockServer.URL)
		if err == nil {
			t.Error("Expected error when save fails")
		}
	})
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

	// Legacy webhook handler just validates signature and returns 200
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", rec.Code, rec.Body.String())
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
