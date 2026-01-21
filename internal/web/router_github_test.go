package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mikelady/roxas/internal/auth"
)

// =============================================================================
// Mock GitHub OAuth Provider
// =============================================================================

type MockGitHubOAuthProvider struct {
	AuthURL       string
	ExchangeError error
	Tokens        *OAuthTokens
}

func (m *MockGitHubOAuthProvider) GetAuthURL(state, redirectURL string) string {
	if m.AuthURL != "" {
		return m.AuthURL + "?state=" + state + "&redirect_uri=" + redirectURL
	}
	return "https://github.com/login/oauth/authorize?state=" + state + "&redirect_uri=" + redirectURL
}

func (m *MockGitHubOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error) {
	if m.ExchangeError != nil {
		return nil, m.ExchangeError
	}
	if m.Tokens != nil {
		return m.Tokens, nil
	}
	return &OAuthTokens{
		AccessToken:    "test_access_token",
		PlatformUserID: "testuser",
		Scopes:         "repo admin:repo_hook",
	}, nil
}

// =============================================================================
// Mock Credential Store
// =============================================================================

type MockCredentialStore struct {
	SavedCreds *PlatformCredentials
	SaveError  error
}

func (m *MockCredentialStore) SaveCredentials(ctx context.Context, creds *PlatformCredentials) error {
	if m.SaveError != nil {
		return m.SaveError
	}
	m.SavedCreds = creds
	return nil
}

// =============================================================================
// GitHub OAuth Route Tests (alice-58, alice-81)
// =============================================================================

func TestRouter_GetOAuthGitHub_RedirectsToLogin_WhenNotAuthenticated(t *testing.T) {
	userStore := NewMockUserStore()
	mockOAuth := &MockGitHubOAuthProvider{}
	mockCredStore := &MockCredentialStore{}
	router := NewRouterWithGitHubOAuth(userStore, mockOAuth, mockCredStore, "https://example.com")

	req := httptest.NewRequest(http.MethodGet, "/oauth/github", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to login
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status %d, got %d", http.StatusSeeOther, rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

func TestRouter_GetOAuthGitHub_RedirectsToGitHub_WhenAuthenticated(t *testing.T) {
	userStore := NewMockUserStore()
	mockOAuth := &MockGitHubOAuthProvider{}
	mockCredStore := &MockCredentialStore{}
	router := NewRouterWithGitHubOAuth(userStore, mockOAuth, mockCredStore, "https://example.com")

	// Create a user and get an auth token
	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/github", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to GitHub
	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("Expected status %d, got %d", http.StatusTemporaryRedirect, rr.Code)
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "github.com") {
		t.Errorf("Expected redirect to GitHub, got %s", location)
	}

	// Should set state cookie
	cookies := rr.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "github_oauth_state" {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Error("Expected github_oauth_state cookie to be set")
	}
}

func TestRouter_GetOAuthGitHub_IncludesStateInRedirectURL(t *testing.T) {
	userStore := NewMockUserStore()
	mockOAuth := &MockGitHubOAuthProvider{}
	mockCredStore := &MockCredentialStore{}
	router := NewRouterWithGitHubOAuth(userStore, mockOAuth, mockCredStore, "https://example.com")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/github", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "state=") {
		t.Errorf("Expected state parameter in redirect URL, got %s", location)
	}
}

func TestRouter_GetOAuthGitHubCallback_RedirectsToLogin_WhenNotAuthenticated(t *testing.T) {
	userStore := NewMockUserStore()
	mockOAuth := &MockGitHubOAuthProvider{}
	mockCredStore := &MockCredentialStore{}
	router := NewRouterWithGitHubOAuth(userStore, mockOAuth, mockCredStore, "https://example.com")

	req := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?code=test_code&state=test_state", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to login
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status %d, got %d", http.StatusSeeOther, rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

func TestRouter_GetOAuthGitHubCallback_ReturnsError_WhenMissingState(t *testing.T) {
	userStore := NewMockUserStore()
	mockOAuth := &MockGitHubOAuthProvider{}
	mockCredStore := &MockCredentialStore{}
	router := NewRouterWithGitHubOAuth(userStore, mockOAuth, mockCredStore, "https://example.com")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?code=test_code", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return error
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestRouter_GetOAuthGitHubCallback_ReturnsError_WhenInvalidState(t *testing.T) {
	userStore := NewMockUserStore()
	mockOAuth := &MockGitHubOAuthProvider{}
	mockCredStore := &MockCredentialStore{}
	router := NewRouterWithGitHubOAuth(userStore, mockOAuth, mockCredStore, "https://example.com")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?code=test_code&state=wrong_state", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	req.AddCookie(&http.Cookie{Name: "github_oauth_state", Value: "expected_state"})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return error
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestRouter_GetOAuthGitHubCallback_ReturnsError_WhenMissingCode(t *testing.T) {
	userStore := NewMockUserStore()
	mockOAuth := &MockGitHubOAuthProvider{}
	mockCredStore := &MockCredentialStore{}
	router := NewRouterWithGitHubOAuth(userStore, mockOAuth, mockCredStore, "https://example.com")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?state=test_state", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	req.AddCookie(&http.Cookie{Name: "github_oauth_state", Value: "test_state"})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return error
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestRouter_GetOAuthGitHubCallback_ExchangesCodeAndStoresCredentials(t *testing.T) {
	userStore := NewMockUserStore()
	mockOAuth := &MockGitHubOAuthProvider{
		Tokens: &OAuthTokens{
			AccessToken:    "ghp_test_token",
			PlatformUserID: "testuser123",
			Scopes:         "repo admin:repo_hook",
		},
	}
	mockCredStore := &MockCredentialStore{}
	router := NewRouterWithGitHubOAuth(userStore, mockOAuth, mockCredStore, "https://example.com")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?code=test_code&state=test_state", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	req.AddCookie(&http.Cookie{Name: "github_oauth_state", Value: "test_state"})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to repo selection
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status %d, got %d", http.StatusSeeOther, rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/repositories/new" {
		t.Errorf("Expected redirect to /repositories/new, got %s", location)
	}

	// Should have saved credentials
	if mockCredStore.SavedCreds == nil {
		t.Error("Expected credentials to be saved")
	} else {
		if mockCredStore.SavedCreds.Platform != "github" {
			t.Errorf("Expected platform 'github', got %s", mockCredStore.SavedCreds.Platform)
		}
		if mockCredStore.SavedCreds.AccessToken != "ghp_test_token" {
			t.Errorf("Expected access token 'ghp_test_token', got %s", mockCredStore.SavedCreds.AccessToken)
		}
		if mockCredStore.SavedCreds.PlatformUserID != "testuser123" {
			t.Errorf("Expected platform user ID 'testuser123', got %s", mockCredStore.SavedCreds.PlatformUserID)
		}
		if mockCredStore.SavedCreds.UserID != user.ID {
			t.Errorf("Expected user ID %s, got %s", user.ID, mockCredStore.SavedCreds.UserID)
		}
	}
}

func TestRouter_GetOAuthGitHubCallback_HandlesGitHubError(t *testing.T) {
	userStore := NewMockUserStore()
	mockOAuth := &MockGitHubOAuthProvider{}
	mockCredStore := &MockCredentialStore{}
	router := NewRouterWithGitHubOAuth(userStore, mockOAuth, mockCredStore, "https://example.com")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?error=access_denied&error_description=User+denied+access", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return error
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "access_denied") {
		t.Errorf("Expected error message to contain 'access_denied', got %s", body)
	}
}

func TestRouter_GetOAuthGitHubCallback_ClearsStateCookie(t *testing.T) {
	userStore := NewMockUserStore()
	mockOAuth := &MockGitHubOAuthProvider{}
	mockCredStore := &MockCredentialStore{}
	router := NewRouterWithGitHubOAuth(userStore, mockOAuth, mockCredStore, "https://example.com")

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?code=test_code&state=test_state", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	req.AddCookie(&http.Cookie{Name: "github_oauth_state", Value: "test_state"})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should clear state cookie
	cookies := rr.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "github_oauth_state" {
			if c.MaxAge != -1 {
				t.Errorf("Expected state cookie to be cleared (MaxAge -1), got MaxAge %d", c.MaxAge)
			}
			break
		}
	}
}

func TestRouter_GetOAuthGitHub_ReturnsError_WhenProviderNotConfigured(t *testing.T) {
	userStore := NewMockUserStore()
	// Create router without GitHub OAuth provider
	router := NewRouterWithStores(userStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/github", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return error
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

// =============================================================================
// GitHub OAuth Provider Tests (alice-57)
// =============================================================================

func TestMockGitHubOAuthProvider_GetAuthURL_IncludesRequiredParams(t *testing.T) {
	provider := &MockGitHubOAuthProvider{}
	authURL := provider.GetAuthURL("test_state", "https://example.com/callback")

	if !strings.Contains(authURL, "state=test_state") {
		t.Errorf("Expected state param in URL, got %s", authURL)
	}

	if !strings.Contains(authURL, "redirect_uri=") {
		t.Errorf("Expected redirect_uri param in URL, got %s", authURL)
	}
}

func TestMockGitHubOAuthProvider_ExchangeCode_ReturnsTokens(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)
	provider := &MockGitHubOAuthProvider{
		Tokens: &OAuthTokens{
			AccessToken:    "test_token",
			RefreshToken:   "refresh_token",
			ExpiresAt:      &expiresAt,
			PlatformUserID: "user123",
			Scopes:         "repo",
		},
	}

	tokens, err := provider.ExchangeCode(context.Background(), "test_code", "https://example.com/callback")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if tokens.AccessToken != "test_token" {
		t.Errorf("Expected access token 'test_token', got %s", tokens.AccessToken)
	}

	if tokens.PlatformUserID != "user123" {
		t.Errorf("Expected platform user ID 'user123', got %s", tokens.PlatformUserID)
	}
}
