package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mikelady/roxas/internal/services"
)

func TestThreadsOAuthProvider_Platform(t *testing.T) {
	provider := NewThreadsOAuthProvider("client-id", "client-secret")
	if got := provider.Platform(); got != services.PlatformThreads {
		t.Errorf("Platform() = %q, want %q", got, services.PlatformThreads)
	}
}

func TestThreadsOAuthProvider_GetAuthURL(t *testing.T) {
	provider := NewThreadsOAuthProvider("test-client-id", "test-client-secret")

	state := "random-state-123"
	redirectURL := "https://example.com/callback"

	authURL := provider.GetAuthURL(state, redirectURL)

	// Parse the URL
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("GetAuthURL() returned invalid URL: %v", err)
	}

	// Check base URL
	if parsed.Host != "www.threads.net" {
		t.Errorf("GetAuthURL() host = %q, want %q", parsed.Host, "www.threads.net")
	}
	if parsed.Path != "/oauth/authorize" {
		t.Errorf("GetAuthURL() path = %q, want %q", parsed.Path, "/oauth/authorize")
	}

	// Check query parameters
	params := parsed.Query()

	if got := params.Get("client_id"); got != "test-client-id" {
		t.Errorf("GetAuthURL() client_id = %q, want %q", got, "test-client-id")
	}

	if got := params.Get("redirect_uri"); got != redirectURL {
		t.Errorf("GetAuthURL() redirect_uri = %q, want %q", got, redirectURL)
	}

	if got := params.Get("state"); got != state {
		t.Errorf("GetAuthURL() state = %q, want %q", got, state)
	}

	if got := params.Get("response_type"); got != "code" {
		t.Errorf("GetAuthURL() response_type = %q, want %q", got, "code")
	}

	// Check scopes are included
	scope := params.Get("scope")
	requiredScopes := provider.GetRequiredScopes()
	for _, s := range requiredScopes {
		if !strings.Contains(scope, s) {
			t.Errorf("GetAuthURL() scope missing %q, got %q", s, scope)
		}
	}
}

func TestThreadsOAuthProvider_GetRequiredScopes(t *testing.T) {
	provider := NewThreadsOAuthProvider("client-id", "client-secret")

	scopes := provider.GetRequiredScopes()

	expectedScopes := []string{
		"threads_basic",
		"threads_content_publish",
		"threads_manage_insights",
	}

	if len(scopes) != len(expectedScopes) {
		t.Errorf("GetRequiredScopes() returned %d scopes, want %d", len(scopes), len(expectedScopes))
	}

	for _, expected := range expectedScopes {
		found := false
		for _, s := range scopes {
			if s == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetRequiredScopes() missing scope %q", expected)
		}
	}
}

func TestThreadsOAuthProvider_ExchangeCode_Success(t *testing.T) {
	// Create test server for short-lived token exchange
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		if r.URL.Path == "/oauth/access_token" && r.Method == "POST" {
			// Short-lived token exchange
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "short-lived-token-123",
				"user_id":      "12345678901234567",
			})
			return
		}

		if r.URL.Path == "/access_token" && r.Method == "GET" {
			// Long-lived token exchange
			grantType := r.URL.Query().Get("grant_type")
			if grantType != "th_exchange_token" {
				t.Errorf("Expected grant_type=th_exchange_token, got %q", grantType)
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "long-lived-token-456",
				"token_type":   "bearer",
				"expires_in":   5184000, // 60 days
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	provider := &ThreadsOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		HTTPClient:   http.DefaultClient,
		BaseURL:      server.URL,
	}

	tokens, err := provider.ExchangeCode(context.Background(), "auth-code-xyz", "https://example.com/callback")

	if err != nil {
		t.Fatalf("ExchangeCode() error = %v", err)
	}

	if tokens.AccessToken != "long-lived-token-456" {
		t.Errorf("ExchangeCode() AccessToken = %q, want %q", tokens.AccessToken, "long-lived-token-456")
	}

	if tokens.ExpiresAt == nil {
		t.Error("ExchangeCode() ExpiresAt should not be nil")
	} else {
		// Check expiration is roughly 60 days from now
		expectedExpiry := time.Now().Add(60 * 24 * time.Hour)
		diff := tokens.ExpiresAt.Sub(expectedExpiry)
		if diff < -time.Hour || diff > time.Hour {
			t.Errorf("ExchangeCode() ExpiresAt = %v, expected roughly %v", tokens.ExpiresAt, expectedExpiry)
		}
	}

	if callCount != 2 {
		t.Errorf("Expected 2 API calls (short-lived + long-lived exchange), got %d", callCount)
	}
}

func TestThreadsOAuthProvider_ExchangeCode_InvalidCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "The authorization code has expired",
		})
	}))
	defer server.Close()

	provider := &ThreadsOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		HTTPClient:   http.DefaultClient,
		BaseURL:      server.URL,
	}

	_, err := provider.ExchangeCode(context.Background(), "expired-code", "https://example.com/callback")

	if err == nil {
		t.Error("ExchangeCode() should return error for invalid code")
	}

	if !errors.Is(err, services.ErrCodeExchangeFailed) {
		t.Errorf("ExchangeCode() error = %v, want ErrCodeExchangeFailed", err)
	}

	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("ExchangeCode() error should contain 'invalid_grant', got %v", err)
	}
}

func TestThreadsOAuthProvider_ExchangeCode_FallbackToShortLived(t *testing.T) {
	// When long-lived token exchange fails, should return short-lived token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/access_token" {
			// Short-lived token succeeds
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "short-lived-token-123",
				"user_id":      "12345678901234567",
			})
			return
		}

		if r.URL.Path == "/access_token" {
			// Long-lived exchange fails
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	provider := &ThreadsOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		HTTPClient:   http.DefaultClient,
		BaseURL:      server.URL,
	}

	tokens, err := provider.ExchangeCode(context.Background(), "auth-code-xyz", "https://example.com/callback")

	if err != nil {
		t.Fatalf("ExchangeCode() error = %v, should return short-lived token on long-lived exchange failure", err)
	}

	if tokens.AccessToken != "short-lived-token-123" {
		t.Errorf("ExchangeCode() AccessToken = %q, want short-lived token", tokens.AccessToken)
	}

	if tokens.PlatformUserID != "12345678901234567" {
		t.Errorf("ExchangeCode() PlatformUserID = %q, want %q", tokens.PlatformUserID, "12345678901234567")
	}
}

func TestThreadsOAuthProvider_RefreshTokens_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/refresh_access_token" {
			t.Errorf("Expected path /refresh_access_token, got %q", r.URL.Path)
		}

		if r.Method != "GET" {
			t.Errorf("Expected GET method, got %q", r.Method)
		}

		grantType := r.URL.Query().Get("grant_type")
		if grantType != "th_refresh_token" {
			t.Errorf("Expected grant_type=th_refresh_token, got %q", grantType)
		}

		accessToken := r.URL.Query().Get("access_token")
		if accessToken != "old-long-lived-token" {
			t.Errorf("Expected access_token=old-long-lived-token, got %q", accessToken)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "new-long-lived-token",
			"token_type":   "bearer",
			"expires_in":   5184000,
		})
	}))
	defer server.Close()

	provider := &ThreadsOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		HTTPClient:   http.DefaultClient,
		BaseURL:      server.URL,
	}

	tokens, err := provider.RefreshTokens(context.Background(), "old-long-lived-token")

	if err != nil {
		t.Fatalf("RefreshTokens() error = %v", err)
	}

	if tokens.AccessToken != "new-long-lived-token" {
		t.Errorf("RefreshTokens() AccessToken = %q, want %q", tokens.AccessToken, "new-long-lived-token")
	}

	if tokens.ExpiresAt == nil {
		t.Error("RefreshTokens() ExpiresAt should not be nil")
	}
}

func TestThreadsOAuthProvider_RefreshTokens_Expired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "The access token has expired",
		})
	}))
	defer server.Close()

	provider := &ThreadsOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		HTTPClient:   http.DefaultClient,
		BaseURL:      server.URL,
	}

	_, err := provider.RefreshTokens(context.Background(), "expired-token")

	if err == nil {
		t.Error("RefreshTokens() should return error for expired token")
	}

	if !errors.Is(err, services.ErrTokenRefreshFailed) {
		t.Errorf("RefreshTokens() error = %v, want ErrTokenRefreshFailed", err)
	}
}

func TestNewThreadsOAuthProvider(t *testing.T) {
	provider := NewThreadsOAuthProvider("my-client-id", "my-client-secret")

	if provider.ClientID != "my-client-id" {
		t.Errorf("ClientID = %q, want %q", provider.ClientID, "my-client-id")
	}

	if provider.ClientSecret != "my-client-secret" {
		t.Errorf("ClientSecret = %q, want %q", provider.ClientSecret, "my-client-secret")
	}

	if provider.BaseURL != "https://graph.threads.net" {
		t.Errorf("BaseURL = %q, want %q", provider.BaseURL, "https://graph.threads.net")
	}

	if provider.HTTPClient == nil {
		t.Error("HTTPClient should not be nil")
	}
}

func TestThreadsOAuthProvider_InterfaceCompliance(t *testing.T) {
	// Verify that ThreadsOAuthProvider implements services.OAuthProvider
	var _ services.OAuthProvider = (*ThreadsOAuthProvider)(nil)
}
