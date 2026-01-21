package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikelady/roxas/internal/auth"
	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// Mock OAuth Provider for Threads
// =============================================================================

type MockThreadsOAuthProvider struct {
	mu               sync.Mutex
	authURLCalled    bool
	authURLState     string
	authURLRedirect  string
	exchangeCodeCall *exchangeCodeCall
	refreshCall      *refreshCall

	// Configurable responses
	exchangeTokens *services.OAuthTokens
	exchangeError  error
	refreshTokens  *services.OAuthTokens
	refreshError   error
}

type exchangeCodeCall struct {
	code        string
	redirectURL string
}

type refreshCall struct {
	refreshToken string
}

func NewMockThreadsOAuthProvider() *MockThreadsOAuthProvider {
	return &MockThreadsOAuthProvider{}
}

func (p *MockThreadsOAuthProvider) Platform() string {
	return services.PlatformThreads
}

func (p *MockThreadsOAuthProvider) GetAuthURL(state, redirectURL string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.authURLCalled = true
	p.authURLState = state
	p.authURLRedirect = redirectURL
	return "https://www.threads.net/oauth/authorize?client_id=test&state=" + state + "&redirect_uri=" + url.QueryEscape(redirectURL)
}

func (p *MockThreadsOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*services.OAuthTokens, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exchangeCodeCall = &exchangeCodeCall{code: code, redirectURL: redirectURL}
	if p.exchangeError != nil {
		return nil, p.exchangeError
	}
	if p.exchangeTokens != nil {
		return p.exchangeTokens, nil
	}
	// Default successful response
	return &services.OAuthTokens{
		AccessToken:    "test-access-token",
		RefreshToken:   "test-refresh-token",
		PlatformUserID: "threads-user-123",
		Scopes:         "threads_basic threads_content_publish",
		ExpiresAt:      timePtr(time.Now().Add(60 * 24 * time.Hour)),
	}, nil
}

func (p *MockThreadsOAuthProvider) RefreshTokens(ctx context.Context, refreshToken string) (*services.OAuthTokens, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refreshCall = &refreshCall{refreshToken: refreshToken}
	if p.refreshError != nil {
		return nil, p.refreshError
	}
	if p.refreshTokens != nil {
		return p.refreshTokens, nil
	}
	// Default successful response
	return &services.OAuthTokens{
		AccessToken:    "new-access-token",
		RefreshToken:   "new-refresh-token",
		PlatformUserID: "threads-user-123",
		Scopes:         "threads_basic threads_content_publish",
		ExpiresAt:      timePtr(time.Now().Add(60 * 24 * time.Hour)),
	}, nil
}

func (p *MockThreadsOAuthProvider) GetRequiredScopes() []string {
	return []string{"threads_basic", "threads_content_publish"}
}

func timePtr(t time.Time) *time.Time {
	return &t
}

// =============================================================================
// Mock Credential Store for Tests
// =============================================================================

type MockThreadsCredentialStore struct {
	mu          sync.Mutex
	credentials map[string]*services.PlatformCredentials // key: userID:platform
	saveError   error
}

func NewMockThreadsCredentialStore() *MockThreadsCredentialStore {
	return &MockThreadsCredentialStore{
		credentials: make(map[string]*services.PlatformCredentials),
	}
}

func (s *MockThreadsCredentialStore) key(userID, platform string) string {
	return userID + ":" + platform
}

func (s *MockThreadsCredentialStore) GetCredentials(ctx context.Context, userID, platform string) (*services.PlatformCredentials, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	creds, ok := s.credentials[s.key(userID, platform)]
	if !ok {
		return nil, services.ErrCredentialsNotFound
	}
	return creds, nil
}

func (s *MockThreadsCredentialStore) SaveCredentials(ctx context.Context, creds *services.PlatformCredentials) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveError != nil {
		return s.saveError
	}
	s.credentials[s.key(creds.UserID, creds.Platform)] = creds
	return nil
}

func (s *MockThreadsCredentialStore) DeleteCredentials(ctx context.Context, userID, platform string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.credentials, s.key(userID, platform))
	return nil
}

func (s *MockThreadsCredentialStore) GetCredentialsForUser(ctx context.Context, userID string) ([]*services.PlatformCredentials, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*services.PlatformCredentials
	for key, creds := range s.credentials {
		if strings.HasPrefix(key, userID+":") {
			result = append(result, creds)
		}
	}
	return result, nil
}

func (s *MockThreadsCredentialStore) GetExpiringCredentials(ctx context.Context, within time.Duration) ([]*services.PlatformCredentials, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*services.PlatformCredentials
	cutoff := time.Now().Add(within)
	for _, creds := range s.credentials {
		if creds.TokenExpiresAt != nil && creds.TokenExpiresAt.Before(cutoff) {
			result = append(result, creds)
		}
	}
	return result, nil
}

// =============================================================================
// Test: /oauth/threads redirect initiates OAuth flow
// =============================================================================

func TestRouter_GetOAuthThreads_RedirectsToThreadsAuth(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, nil)

	// Create authenticated user session
	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/threads", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to Threads OAuth URL
	if rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status (302/303), got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "threads.net/oauth") {
		t.Errorf("Expected redirect to threads.net/oauth, got %s", location)
	}

	// Should include state parameter
	if !strings.Contains(location, "state=") {
		t.Errorf("Expected state parameter in redirect URL")
	}
}

func TestRouter_GetOAuthThreads_RequiresAuth(t *testing.T) {
	router := NewRouterWithThreadsOAuth(NewMockUserStore(), NewMockThreadsOAuthProvider(), nil)

	req := httptest.NewRequest(http.MethodGet, "/oauth/threads", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to login
	if rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

func TestRouter_GetOAuthThreads_StoresStateInSession(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, nil)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/threads", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// OAuth provider should have been called with a state parameter
	if !oauthProvider.authURLCalled {
		t.Error("Expected OAuth provider GetAuthURL to be called")
	}

	if oauthProvider.authURLState == "" {
		t.Error("Expected non-empty state parameter")
	}
}

// =============================================================================
// Test: /oauth/threads/callback exchanges code for tokens
// =============================================================================

func TestRouter_GetOAuthThreadsCallback_ExchangesCodeForTokens(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	credStore := NewMockThreadsCredentialStore()
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, credStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	// Simulate callback with authorization code
	req := httptest.NewRequest(http.MethodGet, "/oauth/threads/callback?code=auth-code-123&state=valid-state", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	// Also set the state cookie that would have been set during the initial redirect
	req.AddCookie(&http.Cookie{Name: "threads_oauth_state", Value: "valid-state"})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should call ExchangeCode on the provider
	if oauthProvider.exchangeCodeCall == nil {
		t.Fatal("Expected ExchangeCode to be called")
	}

	if oauthProvider.exchangeCodeCall.code != "auth-code-123" {
		t.Errorf("Expected code 'auth-code-123', got %q", oauthProvider.exchangeCodeCall.code)
	}
}

func TestRouter_GetOAuthThreadsCallback_RequiresAuth(t *testing.T) {
	router := NewRouterWithThreadsOAuth(NewMockUserStore(), NewMockThreadsOAuthProvider(), nil)

	req := httptest.NewRequest(http.MethodGet, "/oauth/threads/callback?code=test&state=test", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to login
	if rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

func TestRouter_GetOAuthThreadsCallback_ValidatesState(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, nil)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	// Simulate callback with mismatched state
	req := httptest.NewRequest(http.MethodGet, "/oauth/threads/callback?code=auth-code&state=wrong-state", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	req.AddCookie(&http.Cookie{Name: "threads_oauth_state", Value: "correct-state"})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should not call ExchangeCode due to state mismatch
	if oauthProvider.exchangeCodeCall != nil {
		t.Error("ExchangeCode should not be called with invalid state")
	}

	// Should show error or redirect with error
	// Either 400 Bad Request or redirect to connections with error
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther {
		t.Errorf("Expected error response or redirect, got %d", rr.Code)
	}
}

func TestRouter_GetOAuthThreadsCallback_HandlesExchangeError(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	oauthProvider.exchangeError = services.ErrCodeExchangeFailed
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, nil)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/threads/callback?code=bad-code&state=valid-state", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	req.AddCookie(&http.Cookie{Name: "threads_oauth_state", Value: "valid-state"})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should show error or redirect with error parameter
	if rr.Code == http.StatusOK {
		t.Error("Expected error response when code exchange fails")
	}
}

func TestRouter_GetOAuthThreadsCallback_HandlesMissingCode(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, nil)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	// Missing code parameter
	req := httptest.NewRequest(http.MethodGet, "/oauth/threads/callback?state=valid-state", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	req.AddCookie(&http.Cookie{Name: "threads_oauth_state", Value: "valid-state"})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should not call ExchangeCode
	if oauthProvider.exchangeCodeCall != nil {
		t.Error("ExchangeCode should not be called without code parameter")
	}
}

func TestRouter_GetOAuthThreadsCallback_HandlesOAuthError(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, nil)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	// User denied access - Threads sends error parameter
	req := httptest.NewRequest(http.MethodGet, "/oauth/threads/callback?error=access_denied&error_description=User+denied+access", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should handle gracefully without calling ExchangeCode
	if oauthProvider.exchangeCodeCall != nil {
		t.Error("ExchangeCode should not be called when error parameter present")
	}
}

// =============================================================================
// Test: Credential and username storage
// =============================================================================

func TestRouter_GetOAuthThreadsCallback_StoresCredentials(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	credStore := NewMockThreadsCredentialStore()
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, credStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/threads/callback?code=auth-code-123&state=valid-state", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	req.AddCookie(&http.Cookie{Name: "threads_oauth_state", Value: "valid-state"})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should store credentials in the credential store
	creds, err := credStore.GetCredentials(context.Background(), user.ID, services.PlatformThreads)
	if err != nil {
		t.Fatalf("Expected credentials to be stored, got error: %v", err)
	}

	if creds.AccessToken != "test-access-token" {
		t.Errorf("Expected access token 'test-access-token', got %q", creds.AccessToken)
	}

	if creds.RefreshToken != "test-refresh-token" {
		t.Errorf("Expected refresh token 'test-refresh-token', got %q", creds.RefreshToken)
	}

	if creds.PlatformUserID != "threads-user-123" {
		t.Errorf("Expected platform user ID 'threads-user-123', got %q", creds.PlatformUserID)
	}
}

func TestRouter_GetOAuthThreadsCallback_StoresUsername(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	// Configure provider to return username
	oauthProvider.exchangeTokens = &services.OAuthTokens{
		AccessToken:    "test-access-token",
		RefreshToken:   "test-refresh-token",
		PlatformUserID: "threads-user-123",
		Scopes:         "threads_basic threads_content_publish",
		ExpiresAt:      timePtr(time.Now().Add(60 * 24 * time.Hour)),
	}
	credStore := NewMockThreadsCredentialStore()
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, credStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/threads/callback?code=auth-code-123&state=valid-state", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	req.AddCookie(&http.Cookie{Name: "threads_oauth_state", Value: "valid-state"})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should store credentials with platform user ID
	creds, err := credStore.GetCredentials(context.Background(), user.ID, services.PlatformThreads)
	if err != nil {
		t.Fatalf("Expected credentials to be stored, got error: %v", err)
	}

	// Platform user ID should be stored (this is used to fetch username via API)
	if creds.PlatformUserID == "" {
		t.Error("Expected PlatformUserID to be stored")
	}
}

func TestRouter_GetOAuthThreadsCallback_RedirectsToConnectionsOnSuccess(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	credStore := NewMockThreadsCredentialStore()
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, credStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/threads/callback?code=auth-code-123&state=valid-state", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	req.AddCookie(&http.Cookie{Name: "threads_oauth_state", Value: "valid-state"})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to connections page on success
	if rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "/connections") {
		t.Errorf("Expected redirect to /connections, got %s", location)
	}

	// Should include success indicator
	if !strings.Contains(location, "connected=threads") {
		t.Errorf("Expected connected=threads in redirect URL, got %s", location)
	}
}

func TestRouter_GetOAuthThreadsCallback_HandlesCredentialStoreError(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	credStore := NewMockThreadsCredentialStore()
	credStore.saveError = services.ErrCredentialsNotFound // Simulate save error
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, credStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodGet, "/oauth/threads/callback?code=auth-code-123&state=valid-state", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	req.AddCookie(&http.Cookie{Name: "threads_oauth_state", Value: "valid-state"})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should show error when credential storage fails
	if rr.Code == http.StatusOK {
		body := rr.Body.String()
		if strings.Contains(body, "connected=threads") {
			t.Error("Should not indicate success when credential storage fails")
		}
	}
}

// =============================================================================
// Test: Token refresh
// =============================================================================

func TestRouter_ThreadsTokenRefresh_RefreshesExpiredToken(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	credStore := NewMockThreadsCredentialStore()
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, credStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Store expired credentials
	expiredTime := time.Now().Add(-1 * time.Hour)
	credStore.SaveCredentials(context.Background(), &services.PlatformCredentials{
		UserID:         user.ID,
		Platform:       services.PlatformThreads,
		AccessToken:    "expired-access-token",
		RefreshToken:   "valid-refresh-token",
		TokenExpiresAt: &expiredTime,
		PlatformUserID: "threads-user-123",
	})

	token, _ := auth.GenerateToken(user.ID, user.Email)

	// Make request that triggers token refresh
	req := httptest.NewRequest(http.MethodPost, "/oauth/threads/refresh", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should call RefreshTokens on the provider
	if oauthProvider.refreshCall == nil {
		t.Fatal("Expected RefreshTokens to be called")
	}

	if oauthProvider.refreshCall.refreshToken != "valid-refresh-token" {
		t.Errorf("Expected refresh token 'valid-refresh-token', got %q", oauthProvider.refreshCall.refreshToken)
	}
}

func TestRouter_ThreadsTokenRefresh_UpdatesStoredCredentials(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	credStore := NewMockThreadsCredentialStore()
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, credStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Store credentials that need refresh
	expiredTime := time.Now().Add(-1 * time.Hour)
	credStore.SaveCredentials(context.Background(), &services.PlatformCredentials{
		UserID:         user.ID,
		Platform:       services.PlatformThreads,
		AccessToken:    "old-access-token",
		RefreshToken:   "old-refresh-token",
		TokenExpiresAt: &expiredTime,
		PlatformUserID: "threads-user-123",
	})

	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/oauth/threads/refresh", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Credentials should be updated with new tokens
	creds, err := credStore.GetCredentials(context.Background(), user.ID, services.PlatformThreads)
	if err != nil {
		t.Fatalf("Expected credentials to exist, got error: %v", err)
	}

	if creds.AccessToken != "new-access-token" {
		t.Errorf("Expected new access token, got %q", creds.AccessToken)
	}

	if creds.RefreshToken != "new-refresh-token" {
		t.Errorf("Expected new refresh token, got %q", creds.RefreshToken)
	}
}

func TestRouter_ThreadsTokenRefresh_HandlesRefreshError(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	oauthProvider.refreshError = services.ErrTokenRefreshFailed
	credStore := NewMockThreadsCredentialStore()
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, credStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))

	// Store credentials
	expiredTime := time.Now().Add(-1 * time.Hour)
	credStore.SaveCredentials(context.Background(), &services.PlatformCredentials{
		UserID:         user.ID,
		Platform:       services.PlatformThreads,
		AccessToken:    "old-access-token",
		RefreshToken:   "invalid-refresh-token",
		TokenExpiresAt: &expiredTime,
		PlatformUserID: "threads-user-123",
	})

	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/oauth/threads/refresh", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return error status
	if rr.Code == http.StatusOK {
		t.Error("Expected error response when token refresh fails")
	}
}

func TestRouter_ThreadsTokenRefresh_RequiresAuth(t *testing.T) {
	router := NewRouterWithThreadsOAuth(NewMockUserStore(), NewMockThreadsOAuthProvider(), nil)

	req := httptest.NewRequest(http.MethodPost, "/oauth/threads/refresh", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should redirect to login
	if rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther && rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected redirect or unauthorized status, got %d", rr.Code)
	}
}

func TestRouter_ThreadsTokenRefresh_RequiresExistingCredentials(t *testing.T) {
	userStore := NewMockUserStore()
	oauthProvider := NewMockThreadsOAuthProvider()
	credStore := NewMockThreadsCredentialStore() // Empty store
	router := NewRouterWithThreadsOAuth(userStore, oauthProvider, credStore)

	user, _ := userStore.CreateUser(context.Background(), "test@example.com", hashPassword("password123"))
	token, _ := auth.GenerateToken(user.ID, user.Email)

	req := httptest.NewRequest(http.MethodPost, "/oauth/threads/refresh", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Should return error when no credentials exist
	if rr.Code == http.StatusOK {
		t.Error("Expected error response when no credentials exist")
	}

	// Should NOT call RefreshTokens
	if oauthProvider.refreshCall != nil {
		t.Error("RefreshTokens should not be called when no credentials exist")
	}
}
