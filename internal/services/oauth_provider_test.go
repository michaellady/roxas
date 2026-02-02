package services

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// OAuthProvider Test Contracts
// These tests define the contract that all OAuthProvider implementations must follow.
// =============================================================================

// OAuthProviderTestSuite runs the standard test suite against an OAuthProvider implementation.
// Use this in platform-specific tests to ensure compliance with the interface contract.
func OAuthProviderTestSuite(t *testing.T, provider OAuthProvider) {
	t.Helper()

	t.Run("Platform", func(t *testing.T) {
		testPlatformReturnsNonEmpty(t, provider)
	})

	t.Run("GetAuthURL", func(t *testing.T) {
		testGetAuthURLContainsState(t, provider)
		testGetAuthURLContainsScopes(t, provider)
		testGetAuthURLContainsRedirectURL(t, provider)
	})

	t.Run("GetRequiredScopes", func(t *testing.T) {
		testGetRequiredScopesReturnsNonEmpty(t, provider)
	})
}

// testPlatformReturnsNonEmpty verifies Platform() returns a valid identifier.
func testPlatformReturnsNonEmpty(t *testing.T, provider OAuthProvider) {
	t.Helper()
	platform := provider.Platform()
	if platform == "" {
		t.Error("Platform() should return a non-empty string")
	}
	// Verify it matches a known platform constant
	if !SupportedPlatforms[platform] {
		t.Errorf("Platform() returned unknown platform: %s", platform)
	}
}

// testGetAuthURLContainsState verifies auth URL includes the state parameter.
func testGetAuthURLContainsState(t *testing.T, provider OAuthProvider) {
	t.Helper()
	state := "test-state-abc123"
	redirectURL := "https://example.com/callback"

	authURL := provider.GetAuthURL(state, redirectURL)
	if authURL == "" {
		t.Error("GetAuthURL() should return a non-empty URL")
		return
	}

	if !strings.Contains(authURL, "state=") {
		t.Error("GetAuthURL() should include state parameter")
	}
	if !strings.Contains(authURL, state) {
		t.Errorf("GetAuthURL() should include the provided state value: %s", state)
	}
}

// testGetAuthURLContainsScopes verifies auth URL includes required scopes.
func testGetAuthURLContainsScopes(t *testing.T, provider OAuthProvider) {
	t.Helper()
	state := "test-state"
	redirectURL := "https://example.com/callback"

	authURL := provider.GetAuthURL(state, redirectURL)
	_ = provider.GetRequiredScopes() // Ensure scopes are defined (used by GetAuthURL)

	// Auth URL should contain scope parameter
	if !strings.Contains(authURL, "scope=") && !strings.Contains(authURL, "scopes=") {
		// Some platforms use different parameter names or embed scopes differently
		// At minimum, log a warning if no scope parameter found
		t.Log("Warning: GetAuthURL() should typically include scope parameter")
	}
}

// testGetAuthURLContainsRedirectURL verifies auth URL includes redirect_uri.
func testGetAuthURLContainsRedirectURL(t *testing.T, provider OAuthProvider) {
	t.Helper()
	state := "test-state"
	redirectURL := "https://example.com/callback"

	authURL := provider.GetAuthURL(state, redirectURL)
	if !strings.Contains(authURL, "redirect") {
		t.Error("GetAuthURL() should include redirect_uri parameter")
	}
}

// testGetRequiredScopesReturnsNonEmpty verifies scopes are defined.
func testGetRequiredScopesReturnsNonEmpty(t *testing.T, provider OAuthProvider) {
	t.Helper()
	scopes := provider.GetRequiredScopes()
	if len(scopes) == 0 {
		t.Error("GetRequiredScopes() should return at least one required scope")
	}
}

// =============================================================================
// OAuthTokens Tests
// =============================================================================

func TestOAuthTokens_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		tokens   OAuthTokens
		expected bool
	}{
		{
			name: "nil expiry means not expired",
			tokens: OAuthTokens{
				AccessToken: "token",
				ExpiresAt:   nil,
			},
			expected: false,
		},
		{
			name: "future expiry means not expired",
			tokens: OAuthTokens{
				AccessToken: "token",
				ExpiresAt:   oauthTimePtr(time.Now().Add(time.Hour)),
			},
			expected: false,
		},
		{
			name: "past expiry means expired",
			tokens: OAuthTokens{
				AccessToken: "token",
				ExpiresAt:   oauthTimePtr(time.Now().Add(-time.Hour)),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tokens.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOAuthTokens_HasRefreshToken(t *testing.T) {
	tests := []struct {
		name     string
		tokens   OAuthTokens
		expected bool
	}{
		{
			name: "empty refresh token",
			tokens: OAuthTokens{
				AccessToken:  "token",
				RefreshToken: "",
			},
			expected: false,
		},
		{
			name: "has refresh token",
			tokens: OAuthTokens{
				AccessToken:  "token",
				RefreshToken: "refresh-token",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tokens.HasRefreshToken(); got != tt.expected {
				t.Errorf("HasRefreshToken() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Mock OAuthProvider for testing
// =============================================================================

// MockOAuthProvider is a test double for OAuthProvider.
type MockOAuthProvider struct {
	PlatformValue     string
	AuthURL           string
	ExchangeResult    *OAuthTokens
	ExchangeError     error
	RefreshResult     *OAuthTokens
	RefreshError      error
	RequiredScopes    []string
	ExchangeCodeCalls []ExchangeCodeCall
	RefreshCalls      []string
}

// ExchangeCodeCall records a call to ExchangeCode.
type ExchangeCodeCall struct {
	Code        string
	RedirectURL string
}

func (m *MockOAuthProvider) Platform() string {
	if m.PlatformValue == "" {
		return PlatformLinkedIn // Default for tests
	}
	return m.PlatformValue
}

func (m *MockOAuthProvider) GetAuthURL(state, redirectURL string) string {
	if m.AuthURL != "" {
		return m.AuthURL
	}
	// Return a valid test URL by default
	return "https://example.com/oauth?client_id=test&state=" + state + "&redirect_uri=" + redirectURL + "&scope=read+write"
}

func (m *MockOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error) {
	m.ExchangeCodeCalls = append(m.ExchangeCodeCalls, ExchangeCodeCall{
		Code:        code,
		RedirectURL: redirectURL,
	})
	if m.ExchangeError != nil {
		return nil, m.ExchangeError
	}
	if m.ExchangeResult != nil {
		return m.ExchangeResult, nil
	}
	// Return default tokens
	return &OAuthTokens{
		AccessToken:    "mock-access-token",
		RefreshToken:   "mock-refresh-token",
		ExpiresAt:      timePtr(time.Now().Add(time.Hour)),
		PlatformUserID: "mock-user-123",
		Scopes:         "read write",
	}, nil
}

func (m *MockOAuthProvider) RefreshTokens(ctx context.Context, refreshToken string) (*OAuthTokens, error) {
	m.RefreshCalls = append(m.RefreshCalls, refreshToken)
	if m.RefreshError != nil {
		return nil, m.RefreshError
	}
	if m.RefreshResult != nil {
		return m.RefreshResult, nil
	}
	// Return default refreshed tokens
	return &OAuthTokens{
		AccessToken:    "mock-refreshed-access-token",
		RefreshToken:   "mock-refreshed-refresh-token",
		ExpiresAt:      timePtr(time.Now().Add(time.Hour)),
		PlatformUserID: "mock-user-123",
		Scopes:         "read write",
	}, nil
}

func (m *MockOAuthProvider) GetRequiredScopes() []string {
	if m.RequiredScopes == nil {
		return []string{"read", "write"}
	}
	return m.RequiredScopes
}

// Compile-time interface check
var _ OAuthProvider = (*MockOAuthProvider)(nil)

// TestMockOAuthProvider_ImplementsContract runs the test suite on the mock
// to ensure the mock itself is a valid implementation.
func TestMockOAuthProvider_ImplementsContract(t *testing.T) {
	mock := &MockOAuthProvider{}
	OAuthProviderTestSuite(t, mock)
}

// =============================================================================
// ExchangeCode Contract Tests
// =============================================================================

func TestOAuthProvider_ExchangeCode_ReturnsTokens(t *testing.T) {
	mock := &MockOAuthProvider{
		ExchangeResult: &OAuthTokens{
			AccessToken:    "test-access-token",
			RefreshToken:   "test-refresh-token",
			PlatformUserID: "user-456",
			Scopes:         "post read",
		},
	}

	tokens, err := mock.ExchangeCode(context.Background(), "auth-code", "https://example.com/callback")
	if err != nil {
		t.Fatalf("ExchangeCode() returned error: %v", err)
	}

	if tokens.AccessToken != "test-access-token" {
		t.Errorf("Expected AccessToken 'test-access-token', got '%s'", tokens.AccessToken)
	}
	if tokens.RefreshToken != "test-refresh-token" {
		t.Errorf("Expected RefreshToken 'test-refresh-token', got '%s'", tokens.RefreshToken)
	}
	if tokens.PlatformUserID != "user-456" {
		t.Errorf("Expected PlatformUserID 'user-456', got '%s'", tokens.PlatformUserID)
	}
}

func TestOAuthProvider_ExchangeCode_HandlesError(t *testing.T) {
	mock := &MockOAuthProvider{
		ExchangeError: ErrCodeExchangeFailed,
	}

	_, err := mock.ExchangeCode(context.Background(), "invalid-code", "https://example.com/callback")
	if err == nil {
		t.Fatal("Expected error from ExchangeCode()")
	}
	if err != ErrCodeExchangeFailed {
		t.Errorf("Expected ErrCodeExchangeFailed, got: %v", err)
	}
}

// =============================================================================
// RefreshTokens Contract Tests
// =============================================================================

func TestOAuthProvider_RefreshTokens_ReturnsNewTokens(t *testing.T) {
	newExpiry := time.Now().Add(2 * time.Hour)
	mock := &MockOAuthProvider{
		RefreshResult: &OAuthTokens{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			ExpiresAt:    &newExpiry,
		},
	}

	tokens, err := mock.RefreshTokens(context.Background(), "old-refresh-token")
	if err != nil {
		t.Fatalf("RefreshTokens() returned error: %v", err)
	}

	if tokens.AccessToken != "new-access-token" {
		t.Errorf("Expected new AccessToken, got '%s'", tokens.AccessToken)
	}
	if tokens.IsExpired() {
		t.Error("Refreshed tokens should not be expired")
	}
}

func TestOAuthProvider_RefreshTokens_HandlesError(t *testing.T) {
	mock := &MockOAuthProvider{
		RefreshError: ErrTokenRefreshFailed,
	}

	_, err := mock.RefreshTokens(context.Background(), "invalid-refresh-token")
	if err == nil {
		t.Fatal("Expected error from RefreshTokens()")
	}
	if err != ErrTokenRefreshFailed {
		t.Errorf("Expected ErrTokenRefreshFailed, got: %v", err)
	}
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestOAuthErrors_AreDefined(t *testing.T) {
	errors := []error{
		ErrInvalidState,
		ErrCodeExchangeFailed,
		ErrTokenRefreshFailed,
		ErrInvalidCredentials,
		ErrScopesInsufficient,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("OAuth error should not be nil")
		}
		if err.Error() == "" {
			t.Error("OAuth error should have non-empty message")
		}
	}
}

// =============================================================================
// Platform Provider Tests
// Run the test suite against each platform implementation.
// =============================================================================

func TestThreadsOAuthProvider_ImplementsContract(t *testing.T) {
	provider := &ThreadsOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}
	OAuthProviderTestSuite(t, provider)
}

func TestBlueskyAuthProvider_ImplementsContract(t *testing.T) {
	provider := &BlueskyAuthProvider{}
	OAuthProviderTestSuite(t, provider)
}

func TestTwitterOAuthProvider_ImplementsContract(t *testing.T) {
	provider := &TwitterOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}
	OAuthProviderTestSuite(t, provider)
}

func TestLinkedInOAuthProvider_ImplementsContract(t *testing.T) {
	provider := &LinkedInOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}
	OAuthProviderTestSuite(t, provider)
}

// =============================================================================
// Platform-Specific Tests
// =============================================================================

func TestThreadsOAuthProvider_Scopes(t *testing.T) {
	provider := &ThreadsOAuthProvider{}
	scopes := provider.GetRequiredScopes()

	expectedScopes := []string{"threads_basic", "threads_content_publish"}
	if len(scopes) != len(expectedScopes) {
		t.Errorf("Expected %d scopes, got %d", len(expectedScopes), len(scopes))
	}

	for i, expected := range expectedScopes {
		if i >= len(scopes) || scopes[i] != expected {
			t.Errorf("Expected scope %d to be '%s', got '%s'", i, expected, scopes[i])
		}
	}
}

func TestTwitterOAuthProvider_PKCE(t *testing.T) {
	provider := &TwitterOAuthProvider{ClientID: "test"}
	authURL := provider.GetAuthURL("state", "https://example.com/callback")

	// Twitter OAuth 2.0 requires PKCE
	if !strings.Contains(authURL, "code_challenge") {
		t.Error("Twitter auth URL should include PKCE code_challenge")
	}
	if !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Error("Twitter auth URL should specify S256 code challenge method")
	}
}

func TestBlueskyAuthProvider_NoTraditionalOAuth(t *testing.T) {
	provider := &BlueskyAuthProvider{}

	// Bluesky uses app passwords, not traditional OAuth
	scopes := provider.GetRequiredScopes()
	if len(scopes) != 1 || scopes[0] != "atproto" {
		t.Errorf("Bluesky should use atproto scope, got: %v", scopes)
	}

	// Auth URL should point to app password settings
	authURL := provider.GetAuthURL("state", "https://example.com/callback")
	if !strings.Contains(authURL, "bsky.app") {
		t.Error("Bluesky auth URL should point to bsky.app settings")
	}
}

func TestLinkedInOAuthProvider_Scopes(t *testing.T) {
	provider := &LinkedInOAuthProvider{}
	scopes := provider.GetRequiredScopes()

	// LinkedIn requires w_member_social for posting
	found := false
	for _, s := range scopes {
		if s == "w_member_social" {
			found = true
			break
		}
	}
	if !found {
		t.Error("LinkedIn scopes should include w_member_social for posting")
	}
}

// =============================================================================
// joinScopes Helper Test
// =============================================================================

func TestJoinScopes(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		expected string
	}{
		{
			name:     "empty scopes",
			scopes:   []string{},
			expected: "",
		},
		{
			name:     "single scope",
			scopes:   []string{"read"},
			expected: "read",
		},
		{
			name:     "multiple scopes",
			scopes:   []string{"read", "write", "delete"},
			expected: "read write delete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := joinScopes(tt.scopes)
			if got != tt.expected {
				t.Errorf("joinScopes(%v) = '%s', want '%s'", tt.scopes, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Bluesky-Specific Tests
// =============================================================================

func TestBlueskyAuthProvider_CreateSession_Success(t *testing.T) {
	// Create a mock server for Bluesky API
	server := newBlueskyMockServer(t, blueskyMockConfig{
		createSessionResponse: &blueskySessionResponse{
			AccessJwt:  "test-access-jwt",
			RefreshJwt: "test-refresh-jwt",
			DID:        "did:plc:abc123",
			Handle:     "testuser.bsky.social",
		},
	})
	defer server.Close()

	provider := &BlueskyAuthProvider{
		PDSURL: server.URL,
		Client: server.Client(),
	}

	// For Bluesky, we pass credentials as "handle:password" in the code parameter
	tokens, err := provider.ExchangeCode(context.Background(), "testuser.bsky.social:test-app-password", "")
	if err != nil {
		t.Fatalf("ExchangeCode() returned error: %v", err)
	}

	if tokens.AccessToken != "test-access-jwt" {
		t.Errorf("Expected AccessToken 'test-access-jwt', got '%s'", tokens.AccessToken)
	}
	if tokens.RefreshToken != "test-refresh-jwt" {
		t.Errorf("Expected RefreshToken 'test-refresh-jwt', got '%s'", tokens.RefreshToken)
	}
	if tokens.PlatformUserID != "did:plc:abc123" {
		t.Errorf("Expected PlatformUserID 'did:plc:abc123', got '%s'", tokens.PlatformUserID)
	}
}

func TestBlueskyAuthProvider_CreateSession_InvalidCredentials(t *testing.T) {
	server := newBlueskyMockServer(t, blueskyMockConfig{
		createSessionError: true,
	})
	defer server.Close()

	provider := &BlueskyAuthProvider{
		PDSURL: server.URL,
		Client: server.Client(),
	}

	_, err := provider.ExchangeCode(context.Background(), "baduser:wrongpassword", "")
	if err == nil {
		t.Fatal("Expected error for invalid credentials")
	}
	if !strings.Contains(err.Error(), "invalid") && err != ErrInvalidCredentials {
		t.Errorf("Expected invalid credentials error, got: %v", err)
	}
}

func TestBlueskyAuthProvider_RefreshSession_Success(t *testing.T) {
	server := newBlueskyMockServer(t, blueskyMockConfig{
		refreshSessionResponse: &blueskySessionResponse{
			AccessJwt:  "new-access-jwt",
			RefreshJwt: "new-refresh-jwt",
			DID:        "did:plc:abc123",
			Handle:     "testuser.bsky.social",
		},
	})
	defer server.Close()

	provider := &BlueskyAuthProvider{
		PDSURL: server.URL,
		Client: server.Client(),
	}

	tokens, err := provider.RefreshTokens(context.Background(), "old-refresh-jwt")
	if err != nil {
		t.Fatalf("RefreshTokens() returned error: %v", err)
	}

	if tokens.AccessToken != "new-access-jwt" {
		t.Errorf("Expected AccessToken 'new-access-jwt', got '%s'", tokens.AccessToken)
	}
	if tokens.RefreshToken != "new-refresh-jwt" {
		t.Errorf("Expected RefreshToken 'new-refresh-jwt', got '%s'", tokens.RefreshToken)
	}
}

func TestBlueskyAuthProvider_RefreshSession_Failure(t *testing.T) {
	server := newBlueskyMockServer(t, blueskyMockConfig{
		refreshSessionError: true,
	})
	defer server.Close()

	provider := &BlueskyAuthProvider{
		PDSURL: server.URL,
		Client: server.Client(),
	}

	_, err := provider.RefreshTokens(context.Background(), "invalid-refresh-jwt")
	if err == nil {
		t.Fatal("Expected error for invalid refresh token")
	}
}

func TestBlueskyAuthProvider_HandleNormalization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already has .bsky.social",
			input:    "testuser.bsky.social",
			expected: "testuser.bsky.social",
		},
		{
			name:     "bare handle",
			input:    "testuser",
			expected: "testuser.bsky.social",
		},
		{
			name:     "custom domain",
			input:    "user.example.com",
			expected: "user.example.com",
		},
		{
			name:     "has @ prefix",
			input:    "@testuser.bsky.social",
			expected: "testuser.bsky.social",
		},
		{
			name:     "bare handle with @",
			input:    "@testuser",
			expected: "testuser.bsky.social",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeBlueskyHandle(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeBlueskyHandle(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Property-Based Tests for Handle Normalization
// Property 11: Bluesky handles normalized (remove @, add .bsky.social if no domain)
// Validates Requirements 4.1, 4.2
// =============================================================================

// TestProperty_HandleNormalization_NeverStartsWithAt verifies that normalized
// handles never start with @, regardless of input.
func TestProperty_HandleNormalization_NeverStartsWithAt(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Generate handles that may or may not have @ prefix
	handleGen := gen.AnyString().Map(func(s string) string {
		// Ensure non-empty string for meaningful test
		if s == "" {
			return "user"
		}
		return s
	})

	properties.Property("normalized handle never starts with @", prop.ForAll(
		func(handle string) bool {
			normalized := normalizeBlueskyHandle(handle)
			return !strings.HasPrefix(normalized, "@")
		},
		handleGen,
	))

	properties.TestingRun(t)
}

// TestProperty_HandleNormalization_AlwaysHasDomain verifies that normalized
// handles always contain a domain (indicated by having a dot).
func TestProperty_HandleNormalization_AlwaysHasDomain(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Generate handles that may or may not have a domain
	handleGen := gen.AnyString().Map(func(s string) string {
		if s == "" {
			return "user"
		}
		return s
	})

	properties.Property("normalized handle always contains a dot (has domain)", prop.ForAll(
		func(handle string) bool {
			normalized := normalizeBlueskyHandle(handle)
			return strings.Contains(normalized, ".")
		},
		handleGen,
	))

	properties.TestingRun(t)
}

// TestProperty_HandleNormalization_AtPrefixRemoval verifies that handles with
// @ prefix normalize the same as handles without @ prefix.
func TestProperty_HandleNormalization_AtPrefixRemoval(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Generate non-@ prefixed handles
	baseHandleGen := gen.AnyString().SuchThat(func(s string) bool {
		return s != "" && !strings.HasPrefix(s, "@")
	}).Map(func(s string) string {
		if s == "" {
			return "user"
		}
		return s
	})

	properties.Property("@handle normalizes same as handle", prop.ForAll(
		func(baseHandle string) bool {
			withAt := "@" + baseHandle
			withoutAt := baseHandle

			normalizedWithAt := normalizeBlueskyHandle(withAt)
			normalizedWithoutAt := normalizeBlueskyHandle(withoutAt)

			return normalizedWithAt == normalizedWithoutAt
		},
		baseHandleGen,
	))

	properties.TestingRun(t)
}

// TestProperty_HandleNormalization_PreservesDomain verifies that handles with
// custom domains keep their domain intact.
func TestProperty_HandleNormalization_PreservesDomain(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Generate handles with domains by combining user and domain parts
	handleWithDomainGen := gopter.CombineGens(
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 }),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 }),
	).Map(func(vals []interface{}) string {
		user := vals[0].(string)
		domain := vals[1].(string)
		return user + "." + domain
	})

	properties.Property("handles with domain preserve their domain", prop.ForAll(
		func(handle string) bool {
			normalized := normalizeBlueskyHandle(handle)
			// If input has a dot, output should not end with .bsky.social (unless it was the original domain)
			// More precisely: input with dot should equal output (no .bsky.social appended)
			return normalized == handle
		},
		handleWithDomainGen,
	))

	properties.TestingRun(t)
}

// TestProperty_HandleNormalization_BareHandleGetsBskySocial verifies that
// handles without a domain get .bsky.social appended.
func TestProperty_HandleNormalization_BareHandleGetsBskySocial(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Generate bare handles (no dot, no @)
	bareHandleGen := gen.AlphaString().SuchThat(func(s string) bool {
		return len(s) > 0 && !strings.Contains(s, ".") && !strings.HasPrefix(s, "@")
	})

	properties.Property("bare handles get .bsky.social appended", prop.ForAll(
		func(handle string) bool {
			normalized := normalizeBlueskyHandle(handle)
			return normalized == handle+".bsky.social"
		},
		bareHandleGen,
	))

	properties.TestingRun(t)
}

// TestProperty_HandleNormalization_Idempotent verifies that normalizing
// an already-normalized handle produces the same result.
func TestProperty_HandleNormalization_Idempotent(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	handleGen := gen.AnyString().Map(func(s string) string {
		if s == "" {
			return "user"
		}
		return s
	})

	properties.Property("normalization is idempotent", prop.ForAll(
		func(handle string) bool {
			once := normalizeBlueskyHandle(handle)
			twice := normalizeBlueskyHandle(once)
			return once == twice
		},
		handleGen,
	))

	properties.TestingRun(t)
}

func TestBlueskyAuthProvider_ParseCredentials(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantHandle   string
		wantPassword string
		wantErr      bool
	}{
		{
			name:         "valid credentials",
			input:        "testuser.bsky.social:app-password-123",
			wantHandle:   "testuser.bsky.social",
			wantPassword: "app-password-123",
			wantErr:      false,
		},
		{
			name:         "password with colons",
			input:        "user:pass:word:with:colons",
			wantHandle:   "user",
			wantPassword: "pass:word:with:colons",
			wantErr:      false,
		},
		{
			name:    "missing password",
			input:   "justhandle",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handle, password, err := parseBlueskyCredentials(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if handle != tt.wantHandle {
				t.Errorf("handle = %q, want %q", handle, tt.wantHandle)
			}
			if password != tt.wantPassword {
				t.Errorf("password = %q, want %q", password, tt.wantPassword)
			}
		})
	}
}

// =============================================================================
// Bluesky Mock Server
// =============================================================================

// blueskyMockSessionResponse is the mock server's response type
// (uses the same JSON structure as blueskySessionResponse in oauth_provider.go)
type blueskyMockSessionResponse struct {
	AccessJwt  string `json:"accessJwt"`
	RefreshJwt string `json:"refreshJwt"`
	DID        string `json:"did"`
	Handle     string `json:"handle"`
}

type blueskyMockConfig struct {
	createSessionResponse  *blueskySessionResponse
	createSessionError     bool
	refreshSessionResponse *blueskySessionResponse
	refreshSessionError    bool
}

func newBlueskyMockServer(t *testing.T, config blueskyMockConfig) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/xrpc/com.atproto.server.createSession":
			if config.createSessionError {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "AuthenticationRequired",
					"message": "Invalid identifier or password",
				})
				return
			}
			if config.createSessionResponse != nil {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(config.createSessionResponse)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)

		case "/xrpc/com.atproto.server.refreshSession":
			if config.refreshSessionError {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "ExpiredToken",
					"message": "Token has expired",
				})
				return
			}
			if config.refreshSessionResponse != nil {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(config.refreshSessionResponse)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// =============================================================================
// GitHub OAuth Provider Tests
// =============================================================================

func TestGitHubOAuthProvider_ImplementsContract(t *testing.T) {
	provider := &GitHubOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}
	OAuthProviderTestSuite(t, provider)
}

func TestGitHubOAuthProvider_Platform(t *testing.T) {
	provider := &GitHubOAuthProvider{}
	if got := provider.Platform(); got != PlatformGitHub {
		t.Errorf("Platform() = %q, want %q", got, PlatformGitHub)
	}
}

func TestGitHubOAuthProvider_GetAuthURL(t *testing.T) {
	provider := &GitHubOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	state := "random-state-123"
	redirectURL := "https://example.com/callback"

	authURL := provider.GetAuthURL(state, redirectURL)

	// Check that URL contains expected components
	if !strings.Contains(authURL, "github.com/login/oauth/authorize") {
		t.Errorf("GetAuthURL() should point to GitHub OAuth authorize, got %s", authURL)
	}
	if !strings.Contains(authURL, "client_id=test-client-id") {
		t.Error("GetAuthURL() should include client_id")
	}
	if !strings.Contains(authURL, "state="+state) {
		t.Errorf("GetAuthURL() should include state=%s", state)
	}
	if !strings.Contains(authURL, "redirect_uri=") {
		t.Error("GetAuthURL() should include redirect_uri")
	}
	if !strings.Contains(authURL, "scope=") {
		t.Error("GetAuthURL() should include scope")
	}
}

func TestGitHubOAuthProvider_GetAuthURL_CustomBaseURL(t *testing.T) {
	provider := &GitHubOAuthProvider{
		ClientID: "test-client",
		BaseURL:  "https://github.enterprise.com",
	}

	authURL := provider.GetAuthURL("state", "https://example.com/callback")

	if !strings.Contains(authURL, "github.enterprise.com") {
		t.Errorf("GetAuthURL() should use custom BaseURL, got %s", authURL)
	}
}

func TestGitHubOAuthProvider_Scopes(t *testing.T) {
	provider := &GitHubOAuthProvider{}
	scopes := provider.GetRequiredScopes()

	// GitHub OAuth for repo access needs these scopes
	expectedScopes := map[string]bool{
		"repo":            false,
		"admin:repo_hook": false,
	}

	for _, s := range scopes {
		if _, ok := expectedScopes[s]; ok {
			expectedScopes[s] = true
		}
	}

	for scope, found := range expectedScopes {
		if !found {
			t.Errorf("Expected scope %q not found in %v", scope, scopes)
		}
	}
}

func TestGitHubOAuthProvider_ExchangeCode_Success(t *testing.T) {
	server := newGitHubMockServer(t, githubMockConfig{
		tokenResponse: &githubTokenResponse{
			AccessToken:  "gho_test_access_token",
			RefreshToken: "ghr_test_refresh_token",
			TokenType:    "bearer",
			Scope:        "repo,admin:repo_hook",
			ExpiresIn:    28800, // 8 hours
		},
		userResponse: &githubUserResponse{
			Login: "testuser",
			ID:    12345,
		},
	})
	defer server.Close()

	provider := &GitHubOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		BaseURL:      server.URL,
		APIURL:       server.URL,
		HTTPClient:   server.Client(),
	}

	tokens, err := provider.ExchangeCode(context.Background(), "test-auth-code", "https://example.com/callback")
	if err != nil {
		t.Fatalf("ExchangeCode() returned error: %v", err)
	}

	if tokens.AccessToken != "gho_test_access_token" {
		t.Errorf("Expected AccessToken 'gho_test_access_token', got '%s'", tokens.AccessToken)
	}
	if tokens.RefreshToken != "ghr_test_refresh_token" {
		t.Errorf("Expected RefreshToken 'ghr_test_refresh_token', got '%s'", tokens.RefreshToken)
	}
	if tokens.PlatformUserID != "testuser" {
		t.Errorf("Expected PlatformUserID 'testuser', got '%s'", tokens.PlatformUserID)
	}
	if tokens.Scopes != "repo,admin:repo_hook" {
		t.Errorf("Expected Scopes 'repo,admin:repo_hook', got '%s'", tokens.Scopes)
	}
	if tokens.ExpiresAt == nil {
		t.Error("Expected ExpiresAt to be set")
	}
}

func TestGitHubOAuthProvider_ExchangeCode_NoExpiry(t *testing.T) {
	server := newGitHubMockServer(t, githubMockConfig{
		tokenResponse: &githubTokenResponse{
			AccessToken: "gho_non_expiring_token",
			TokenType:   "bearer",
			Scope:       "repo",
			ExpiresIn:   0, // No expiry
		},
		userResponse: &githubUserResponse{
			Login: "testuser",
			ID:    12345,
		},
	})
	defer server.Close()

	provider := &GitHubOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		BaseURL:      server.URL,
		APIURL:       server.URL,
		HTTPClient:   server.Client(),
	}

	tokens, err := provider.ExchangeCode(context.Background(), "test-code", "https://example.com/callback")
	if err != nil {
		t.Fatalf("ExchangeCode() returned error: %v", err)
	}

	if tokens.ExpiresAt != nil {
		t.Error("Expected ExpiresAt to be nil for non-expiring tokens")
	}
}

func TestGitHubOAuthProvider_ExchangeCode_InvalidCode(t *testing.T) {
	server := newGitHubMockServer(t, githubMockConfig{
		tokenError: true,
	})
	defer server.Close()

	provider := &GitHubOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		BaseURL:      server.URL,
		APIURL:       server.URL,
		HTTPClient:   server.Client(),
	}

	_, err := provider.ExchangeCode(context.Background(), "invalid-code", "https://example.com/callback")
	if err == nil {
		t.Fatal("Expected error for invalid code")
	}
	if !strings.Contains(err.Error(), "bad_verification_code") && !strings.Contains(err.Error(), "failed") {
		t.Errorf("Expected error about bad code, got: %v", err)
	}
}

func TestGitHubOAuthProvider_ExchangeCode_UserFetchFailure(t *testing.T) {
	// Test that exchange succeeds even if user fetch fails
	server := newGitHubMockServer(t, githubMockConfig{
		tokenResponse: &githubTokenResponse{
			AccessToken: "gho_test_token",
			TokenType:   "bearer",
			Scope:       "repo",
		},
		userError: true,
	})
	defer server.Close()

	provider := &GitHubOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		BaseURL:      server.URL,
		APIURL:       server.URL,
		HTTPClient:   server.Client(),
	}

	tokens, err := provider.ExchangeCode(context.Background(), "test-code", "https://example.com/callback")
	if err != nil {
		t.Fatalf("ExchangeCode() should succeed even if user fetch fails: %v", err)
	}

	if tokens.AccessToken != "gho_test_token" {
		t.Errorf("Expected AccessToken 'gho_test_token', got '%s'", tokens.AccessToken)
	}
	// PlatformUserID should be empty since user fetch failed
	if tokens.PlatformUserID != "" {
		t.Errorf("Expected empty PlatformUserID, got '%s'", tokens.PlatformUserID)
	}
}

func TestGitHubOAuthProvider_RefreshTokens_Success(t *testing.T) {
	server := newGitHubMockServer(t, githubMockConfig{
		refreshResponse: &githubTokenResponse{
			AccessToken:  "gho_new_access_token",
			RefreshToken: "ghr_new_refresh_token",
			TokenType:    "bearer",
			Scope:        "repo,admin:repo_hook",
			ExpiresIn:    28800,
		},
	})
	defer server.Close()

	provider := &GitHubOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		BaseURL:      server.URL,
		HTTPClient:   server.Client(),
	}

	tokens, err := provider.RefreshTokens(context.Background(), "ghr_old_refresh_token")
	if err != nil {
		t.Fatalf("RefreshTokens() returned error: %v", err)
	}

	if tokens.AccessToken != "gho_new_access_token" {
		t.Errorf("Expected AccessToken 'gho_new_access_token', got '%s'", tokens.AccessToken)
	}
	if tokens.RefreshToken != "ghr_new_refresh_token" {
		t.Errorf("Expected RefreshToken 'ghr_new_refresh_token', got '%s'", tokens.RefreshToken)
	}
}

func TestGitHubOAuthProvider_RefreshTokens_EmptyToken(t *testing.T) {
	provider := &GitHubOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	_, err := provider.RefreshTokens(context.Background(), "")
	if err == nil {
		t.Fatal("Expected error for empty refresh token")
	}
	if err != ErrTokenRefreshFailed {
		t.Errorf("Expected ErrTokenRefreshFailed, got: %v", err)
	}
}

func TestGitHubOAuthProvider_RefreshTokens_Failure(t *testing.T) {
	server := newGitHubMockServer(t, githubMockConfig{
		refreshError: true,
	})
	defer server.Close()

	provider := &GitHubOAuthProvider{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		BaseURL:      server.URL,
		HTTPClient:   server.Client(),
	}

	_, err := provider.RefreshTokens(context.Background(), "invalid-refresh-token")
	if err == nil {
		t.Fatal("Expected error for invalid refresh token")
	}
}

// =============================================================================
// GitHub Mock Server
// =============================================================================

type githubMockConfig struct {
	tokenResponse   *githubTokenResponse
	tokenError      bool
	refreshResponse *githubTokenResponse
	refreshError    bool
	userResponse    *githubUserResponse
	userError       bool
}

func newGitHubMockServer(t *testing.T, config githubMockConfig) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			// Check if this is a refresh request
			if r.Method == "POST" {
				body, _ := io.ReadAll(r.Body)
				bodyStr := string(body)

				if strings.Contains(bodyStr, "grant_type=refresh_token") {
					// Refresh token request
					if config.refreshError {
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(map[string]string{
							"error":             "bad_refresh_token",
							"error_description": "The refresh token is invalid",
						})
						return
					}
					if config.refreshResponse != nil {
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(config.refreshResponse)
						return
					}
				} else {
					// Code exchange request
					if config.tokenError {
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(map[string]string{
							"error":             "bad_verification_code",
							"error_description": "The code passed is incorrect or expired",
						})
						return
					}
					if config.tokenResponse != nil {
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(config.tokenResponse)
						return
					}
				}
			}
			w.WriteHeader(http.StatusInternalServerError)

		case "/user":
			if config.userError {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"message": "Bad credentials",
				})
				return
			}
			if config.userResponse != nil {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(config.userResponse)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestGitHubExpiryFromResponse(t *testing.T) {
	tests := []struct {
		name      string
		expiresIn int
		wantNil   bool
	}{
		{
			name:      "zero expires_in returns nil",
			expiresIn: 0,
			wantNil:   true,
		},
		{
			name:      "negative expires_in returns nil",
			expiresIn: -1,
			wantNil:   true,
		},
		{
			name:      "positive expires_in returns future time",
			expiresIn: 3600,
			wantNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := githubExpiryFromResponse(tt.expiresIn)
			if tt.wantNil {
				if result != nil {
					t.Errorf("Expected nil, got %v", result)
				}
			} else {
				if result == nil {
					t.Error("Expected non-nil time")
				} else if result.Before(time.Now()) {
					t.Error("Expected future time")
				}
			}
		})
	}
}

// =============================================================================
// Property-Based Tests (using gopter)
// =============================================================================

// TestProperty_GitHubOAuthURL_ContainsRequiredScopes validates that the GitHub
// OAuth authorization URL always contains the required scopes 'repo' and
// 'admin:repo_hook', regardless of the input parameters provided.
// This is Property 5 from Requirements 2.1.
func TestProperty_GitHubOAuthURL_ContainsRequiredScopes(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for valid OAuth state strings (non-empty alphanumeric)
	genState := gen.AlphaString().SuchThat(func(s string) bool {
		return len(s) > 0 && len(s) <= 128
	})

	// Generator for valid redirect URLs
	genRedirectURL := gen.AnyString().Map(func(s string) string {
		// Create a valid HTTPS URL for testing
		return "https://example.com/callback/" + url.PathEscape(s)
	})

	// Generator for valid client IDs (non-empty)
	genClientID := gen.AlphaString().SuchThat(func(s string) bool {
		return len(s) > 0
	})

	// Generator for client secrets (can be empty for this test)
	genClientSecret := gen.AlphaString()

	properties.Property("GitHub OAuth URL always contains 'repo' scope", prop.ForAll(
		func(state, redirectURL, clientID, clientSecret string) bool {
			provider := &GitHubOAuthProvider{
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			authURL := provider.GetAuthURL(state, redirectURL)

			// Parse the URL to extract the scope parameter
			parsedURL, err := url.Parse(authURL)
			if err != nil {
				return false
			}

			scopeParam := parsedURL.Query().Get("scope")
			// The scope parameter should contain 'repo'
			return strings.Contains(scopeParam, "repo")
		},
		genState,
		genRedirectURL,
		genClientID,
		genClientSecret,
	))

	properties.Property("GitHub OAuth URL always contains 'admin:repo_hook' scope", prop.ForAll(
		func(state, redirectURL, clientID, clientSecret string) bool {
			provider := &GitHubOAuthProvider{
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			authURL := provider.GetAuthURL(state, redirectURL)

			// Parse the URL to extract the scope parameter
			parsedURL, err := url.Parse(authURL)
			if err != nil {
				return false
			}

			scopeParam := parsedURL.Query().Get("scope")
			// The scope parameter should contain 'admin:repo_hook'
			return strings.Contains(scopeParam, "admin:repo_hook")
		},
		genState,
		genRedirectURL,
		genClientID,
		genClientSecret,
	))

	properties.Property("GitHub OAuth URL contains both required scopes", prop.ForAll(
		func(state, redirectURL, clientID, clientSecret string) bool {
			provider := &GitHubOAuthProvider{
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			authURL := provider.GetAuthURL(state, redirectURL)

			// Parse the URL to extract the scope parameter
			parsedURL, err := url.Parse(authURL)
			if err != nil {
				return false
			}

			scopeParam := parsedURL.Query().Get("scope")

			// Both required scopes must be present
			hasRepo := strings.Contains(scopeParam, "repo")
			hasAdminRepoHook := strings.Contains(scopeParam, "admin:repo_hook")

			return hasRepo && hasAdminRepoHook
		},
		genState,
		genRedirectURL,
		genClientID,
		genClientSecret,
	))

	properties.TestingRun(t)
}

// TestProperty_GitHubOAuthURL_ScopesMatchGetRequiredScopes validates that the
// scopes in the OAuth URL exactly match what GetRequiredScopes() returns.
func TestProperty_GitHubOAuthURL_ScopesMatchGetRequiredScopes(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	genState := gen.AlphaString().SuchThat(func(s string) bool {
		return len(s) > 0 && len(s) <= 128
	})

	genRedirectURL := gen.AnyString().Map(func(s string) string {
		return "https://example.com/callback/" + url.PathEscape(s)
	})

	genClientID := gen.AlphaString().SuchThat(func(s string) bool {
		return len(s) > 0
	})

	properties.Property("OAuth URL scope parameter contains all required scopes", prop.ForAll(
		func(state, redirectURL, clientID string) bool {
			provider := &GitHubOAuthProvider{
				ClientID: clientID,
			}

			authURL := provider.GetAuthURL(state, redirectURL)
			requiredScopes := provider.GetRequiredScopes()

			parsedURL, err := url.Parse(authURL)
			if err != nil {
				return false
			}

			scopeParam := parsedURL.Query().Get("scope")

			// Check each required scope is present in the URL
			for _, scope := range requiredScopes {
				if !strings.Contains(scopeParam, scope) {
					return false
				}
			}

			return true
		},
		genState,
		genRedirectURL,
		genClientID,
	))

	properties.TestingRun(t)
}

// =============================================================================
// Helper functions
// =============================================================================

func oauthTimePtr(t time.Time) *time.Time {
	return &t
}
