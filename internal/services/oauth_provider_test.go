package services

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// OAuthTokens Unit Tests
// =============================================================================

func TestOAuthTokens_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt *time.Time
		want      bool
	}{
		{
			name:      "nil expiry never expires",
			expiresAt: nil,
			want:      false,
		},
		{
			name:      "future expiry not expired",
			expiresAt: oauthTimePtr(time.Now().Add(time.Hour)),
			want:      false,
		},
		{
			name:      "past expiry is expired",
			expiresAt: oauthTimePtr(time.Now().Add(-time.Hour)),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := &OAuthTokens{ExpiresAt: tt.expiresAt}
			if got := tokens.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOAuthTokens_ExpiresWithin(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt *time.Time
		duration  time.Duration
		want      bool
	}{
		{
			name:      "nil expiry returns false",
			expiresAt: nil,
			duration:  time.Hour,
			want:      false,
		},
		{
			name:      "expires within window",
			expiresAt: oauthTimePtr(time.Now().Add(30 * time.Minute)),
			duration:  time.Hour,
			want:      true,
		},
		{
			name:      "expires outside window",
			expiresAt: oauthTimePtr(time.Now().Add(2 * time.Hour)),
			duration:  time.Hour,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := &OAuthTokens{ExpiresAt: tt.expiresAt}
			if got := tokens.ExpiresWithin(tt.duration); got != tt.want {
				t.Errorf("ExpiresWithin(%v) = %v, want %v", tt.duration, got, tt.want)
			}
		})
	}
}

func TestOAuthTokens_HasRefreshToken(t *testing.T) {
	tests := []struct {
		name         string
		refreshToken string
		want         bool
	}{
		{
			name:         "empty refresh token",
			refreshToken: "",
			want:         false,
		},
		{
			name:         "has refresh token",
			refreshToken: "refresh_abc123",
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := &OAuthTokens{RefreshToken: tt.refreshToken}
			if got := tokens.HasRefreshToken(); got != tt.want {
				t.Errorf("HasRefreshToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSupportsOAuth(t *testing.T) {
	tests := []struct {
		platform string
		want     bool
	}{
		{AuthProviderThreads, true},
		{AuthProviderTwitter, true},
		{AuthProviderLinkedIn, true},
		{AuthProviderBluesky, false}, // Uses app passwords
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			if got := SupportsOAuth(tt.platform); got != tt.want {
				t.Errorf("SupportsOAuth(%q) = %v, want %v", tt.platform, got, tt.want)
			}
		})
	}
}

// =============================================================================
// OAuthProvider Contract Tests
// These tests define the contract that all OAuthProvider implementations must satisfy
// =============================================================================

// OAuthProviderContractTest runs the standard test suite for an OAuthProvider implementation.
// Implementations should call this in their own test file with a configured provider.
func OAuthProviderContractTest(t *testing.T, provider OAuthProvider) {
	t.Helper()

	t.Run("Platform returns non-empty identifier", func(t *testing.T) {
		platform := provider.Platform()
		if platform == "" {
			t.Error("Platform() returned empty string")
		}
	})

	t.Run("GetRequiredScopes returns non-empty scopes", func(t *testing.T) {
		scopes := provider.GetRequiredScopes()
		if len(scopes) == 0 {
			t.Error("GetRequiredScopes() returned empty slice")
		}
	})

	t.Run("GetAuthURL includes state parameter", func(t *testing.T) {
		state := "test-state-12345"
		redirectURL := "https://example.com/callback"

		authURL := provider.GetAuthURL(state, redirectURL)
		if authURL == "" {
			t.Fatal("GetAuthURL() returned empty string")
		}

		parsed, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("GetAuthURL() returned invalid URL: %v", err)
		}

		gotState := parsed.Query().Get("state")
		if gotState != state {
			t.Errorf("auth URL state = %q, want %q", gotState, state)
		}
	})

	t.Run("GetAuthURL includes redirect_uri", func(t *testing.T) {
		state := "test-state"
		redirectURL := "https://example.com/oauth/callback"

		authURL := provider.GetAuthURL(state, redirectURL)
		parsed, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("GetAuthURL() returned invalid URL: %v", err)
		}

		gotRedirect := parsed.Query().Get("redirect_uri")
		if gotRedirect != redirectURL {
			t.Errorf("auth URL redirect_uri = %q, want %q", gotRedirect, redirectURL)
		}
	})

	t.Run("GetAuthURL includes required scopes", func(t *testing.T) {
		authURL := provider.GetAuthURL("state", "https://example.com/callback")
		requiredScopes := provider.GetRequiredScopes()

		parsed, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("GetAuthURL() returned invalid URL: %v", err)
		}

		scopeParam := parsed.Query().Get("scope")
		for _, scope := range requiredScopes {
			if !strings.Contains(scopeParam, scope) {
				t.Errorf("auth URL missing required scope %q in %q", scope, scopeParam)
			}
		}
	})

	t.Run("ExchangeCode fails with invalid code", func(t *testing.T) {
		ctx := context.Background()
		_, err := provider.ExchangeCode(ctx, "invalid-code", "https://example.com/callback")
		if err == nil {
			t.Error("ExchangeCode() with invalid code should return error")
		}
	})

	t.Run("RefreshTokens fails with invalid token", func(t *testing.T) {
		ctx := context.Background()
		_, err := provider.RefreshTokens(ctx, "invalid-refresh-token")
		// Either ErrTokenRefreshFailed or ErrOAuthNotSupported is acceptable
		if err == nil {
			t.Error("RefreshTokens() with invalid token should return error")
		}
	})
}

// =============================================================================
// Mock OAuthProvider for testing consumers
// =============================================================================

// MockOAuthProvider is a test double for OAuthProvider
type MockOAuthProvider struct {
	PlatformValue      string
	ScopesValue        []string
	AuthURLValue       string
	ExchangeResult     *OAuthTokens
	ExchangeError      error
	RefreshResult      *OAuthTokens
	RefreshError       error

	// Call tracking
	ExchangeCodeCalls  []exchangeCodeCall
	RefreshTokensCalls []string
}

type exchangeCodeCall struct {
	Code        string
	RedirectURL string
}

func (m *MockOAuthProvider) Platform() string {
	if m.PlatformValue == "" {
		return "mock"
	}
	return m.PlatformValue
}

func (m *MockOAuthProvider) GetAuthURL(state, redirectURL string) string {
	if m.AuthURLValue != "" {
		return m.AuthURLValue
	}
	return "https://mock.example.com/oauth/authorize?state=" + state +
		"&redirect_uri=" + url.QueryEscape(redirectURL) +
		"&scope=" + strings.Join(m.GetRequiredScopes(), "%20")
}

func (m *MockOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error) {
	m.ExchangeCodeCalls = append(m.ExchangeCodeCalls, exchangeCodeCall{code, redirectURL})
	if m.ExchangeError != nil {
		return nil, m.ExchangeError
	}
	if m.ExchangeResult != nil {
		return m.ExchangeResult, nil
	}
	return &OAuthTokens{
		AccessToken:    "mock_access_token",
		RefreshToken:   "mock_refresh_token",
		PlatformUserID: "mock_user_123",
		Scopes:         strings.Join(m.GetRequiredScopes(), " "),
	}, nil
}

func (m *MockOAuthProvider) RefreshTokens(ctx context.Context, refreshToken string) (*OAuthTokens, error) {
	m.RefreshTokensCalls = append(m.RefreshTokensCalls, refreshToken)
	if m.RefreshError != nil {
		return nil, m.RefreshError
	}
	if m.RefreshResult != nil {
		return m.RefreshResult, nil
	}
	return &OAuthTokens{
		AccessToken:    "mock_refreshed_token",
		PlatformUserID: "mock_user_123",
		Scopes:         strings.Join(m.GetRequiredScopes(), " "),
	}, nil
}

func (m *MockOAuthProvider) GetRequiredScopes() []string {
	if len(m.ScopesValue) > 0 {
		return m.ScopesValue
	}
	return []string{"read", "write"}
}

// Verify MockOAuthProvider implements OAuthProvider
var _ OAuthProvider = (*MockOAuthProvider)(nil)

// TestMockOAuthProvider_Contract verifies the mock satisfies the contract
func TestMockOAuthProvider_Contract(t *testing.T) {
	mock := &MockOAuthProvider{
		PlatformValue: "mock",
		ScopesValue:   []string{"read", "write"},
		ExchangeError: ErrInvalidAuthCode,
		RefreshError:  ErrTokenRefreshFailed,
	}
	OAuthProviderContractTest(t, mock)
}

// oauthTimePtr is a local helper to avoid redeclaration with credential_store_test.go
func oauthTimePtr(t time.Time) *time.Time {
	return &t
}
