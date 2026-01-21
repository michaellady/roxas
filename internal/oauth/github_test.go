package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mikelady/roxas/internal/services"
)

func TestGitHubOAuthProvider_Platform(t *testing.T) {
	provider := NewGitHubOAuthProvider("client_id", "client_secret")
	if provider.Platform() != services.PlatformGitHub {
		t.Errorf("Expected platform %s, got %s", services.PlatformGitHub, provider.Platform())
	}
}

func TestGitHubOAuthProvider_GetAuthURL(t *testing.T) {
	provider := NewGitHubOAuthProvider("test_client_id", "test_client_secret")
	authURL := provider.GetAuthURL("test_state", "https://example.com/callback")

	// Should contain GitHub OAuth URL
	if !strings.HasPrefix(authURL, "https://github.com/login/oauth/authorize") {
		t.Errorf("Expected GitHub OAuth URL, got %s", authURL)
	}

	// Should contain client_id
	if !strings.Contains(authURL, "client_id=test_client_id") {
		t.Errorf("Expected client_id in URL, got %s", authURL)
	}

	// Should contain state
	if !strings.Contains(authURL, "state=test_state") {
		t.Errorf("Expected state in URL, got %s", authURL)
	}

	// Should contain redirect_uri
	if !strings.Contains(authURL, "redirect_uri=") {
		t.Errorf("Expected redirect_uri in URL, got %s", authURL)
	}

	// Should contain scope
	if !strings.Contains(authURL, "scope=") {
		t.Errorf("Expected scope in URL, got %s", authURL)
	}
}

func TestGitHubOAuthProvider_GetRequiredScopes(t *testing.T) {
	provider := NewGitHubOAuthProvider("client_id", "client_secret")
	scopes := provider.GetRequiredScopes()

	// Should include repo scope
	hasRepo := false
	for _, s := range scopes {
		if s == "repo" {
			hasRepo = true
			break
		}
	}
	if !hasRepo {
		t.Error("Expected 'repo' scope")
	}

	// Should include admin:repo_hook scope
	hasHook := false
	for _, s := range scopes {
		if s == "admin:repo_hook" {
			hasHook = true
			break
		}
	}
	if !hasHook {
		t.Error("Expected 'admin:repo_hook' scope")
	}
}

func TestGitHubOAuthProvider_ExchangeCode_Success(t *testing.T) {
	// Create a mock GitHub server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login/oauth/access_token" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": "ghp_test_token",
				"token_type":   "bearer",
				"scope":        "repo,admin:repo_hook",
			})
			return
		}
		if r.URL.Path == "/user" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"login": "testuser",
				"id":    12345,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	provider := &GitHubOAuthProvider{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		BaseURL:      server.URL,
		APIURL:       server.URL,
	}

	tokens, err := provider.ExchangeCode(context.Background(), "test_code", "https://example.com/callback")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if tokens.AccessToken != "ghp_test_token" {
		t.Errorf("Expected access token 'ghp_test_token', got %s", tokens.AccessToken)
	}

	if tokens.PlatformUserID != "testuser" {
		t.Errorf("Expected platform user ID 'testuser', got %s", tokens.PlatformUserID)
	}
}

func TestGitHubOAuthProvider_ExchangeCode_Error(t *testing.T) {
	// Create a mock GitHub server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "bad_verification_code",
			"error_description": "The code passed is incorrect or expired.",
		})
	}))
	defer server.Close()

	provider := &GitHubOAuthProvider{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		BaseURL:      server.URL,
		APIURL:       server.URL,
	}

	_, err := provider.ExchangeCode(context.Background(), "invalid_code", "https://example.com/callback")
	if err == nil {
		t.Error("Expected error, got nil")
	}
}

func TestGitHubOAuthProvider_ExchangeCode_EmptyToken(t *testing.T) {
	// Create a mock GitHub server that returns empty token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "",
		})
	}))
	defer server.Close()

	provider := &GitHubOAuthProvider{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		BaseURL:      server.URL,
		APIURL:       server.URL,
	}

	_, err := provider.ExchangeCode(context.Background(), "test_code", "https://example.com/callback")
	if err == nil {
		t.Error("Expected error for empty token, got nil")
	}
}

func TestGitHubOAuthProvider_RefreshTokens_ReturnsError(t *testing.T) {
	provider := NewGitHubOAuthProvider("client_id", "client_secret")

	// GitHub tokens don't support refresh
	_, err := provider.RefreshTokens(context.Background(), "refresh_token")
	if err == nil {
		t.Error("Expected error, got nil")
	}
}

func TestGitHubOAuthProvider_GetAuthURL_WithCustomBaseURL(t *testing.T) {
	provider := &GitHubOAuthProvider{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		BaseURL:      "https://github.example.com",
	}

	authURL := provider.GetAuthURL("test_state", "https://example.com/callback")

	if !strings.HasPrefix(authURL, "https://github.example.com/login/oauth/authorize") {
		t.Errorf("Expected custom base URL, got %s", authURL)
	}
}
