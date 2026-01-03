package services

import (
	"context"
	"errors"
	"time"
)

// =============================================================================
// OAuthProvider Interface (hq-s9g)
// Platform-specific OAuth authentication providers
// =============================================================================

// OAuth-related errors
var (
	ErrInvalidAuthCode   = errors.New("invalid authorization code")
	ErrInvalidState      = errors.New("invalid state parameter")
	ErrTokenRefreshFailed = errors.New("token refresh failed")
	ErrOAuthNotSupported = errors.New("OAuth not supported for this platform")
)

// OAuthTokens represents tokens returned from an OAuth flow.
// This is the result of code exchange or token refresh operations.
type OAuthTokens struct {
	// AccessToken is the token used to authenticate API requests
	AccessToken string

	// RefreshToken is used to obtain new access tokens (may be empty for some platforms)
	RefreshToken string

	// ExpiresAt indicates when the access token expires (nil if it doesn't expire)
	ExpiresAt *time.Time

	// PlatformUserID is the user's ID on the platform (e.g., Threads user ID)
	PlatformUserID string

	// Scopes is a space-separated list of granted OAuth scopes
	Scopes string
}

// IsExpired returns true if the access token has expired
func (t *OAuthTokens) IsExpired() bool {
	if t.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*t.ExpiresAt)
}

// ExpiresWithin returns true if the token expires within the given duration
func (t *OAuthTokens) ExpiresWithin(d time.Duration) bool {
	if t.ExpiresAt == nil {
		return false
	}
	return time.Now().Add(d).After(*t.ExpiresAt)
}

// HasRefreshToken returns true if a refresh token is available
func (t *OAuthTokens) HasRefreshToken() bool {
	return t.RefreshToken != ""
}

// OAuthProvider defines the interface for platform-specific OAuth implementations.
// Each social platform that supports OAuth (Threads, Twitter, LinkedIn) implements
// this interface to handle authentication flows.
type OAuthProvider interface {
	// Platform returns the platform identifier (e.g., "threads", "twitter")
	Platform() string

	// GetAuthURL generates the OAuth authorization URL.
	// state: A unique string to prevent CSRF attacks (will be returned in callback)
	// redirectURL: The URL to redirect to after authorization
	// Returns the full authorization URL the user should visit
	GetAuthURL(state, redirectURL string) string

	// ExchangeCode exchanges an authorization code for access tokens.
	// code: The authorization code received from the OAuth callback
	// redirectURL: Must match the redirectURL used in GetAuthURL
	// Returns tokens on success or an error (e.g., ErrInvalidAuthCode)
	ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error)

	// RefreshTokens obtains new tokens using a refresh token.
	// Returns ErrTokenRefreshFailed if the refresh token is invalid or expired.
	// Returns ErrOAuthNotSupported if the platform doesn't support token refresh.
	RefreshTokens(ctx context.Context, refreshToken string) (*OAuthTokens, error)

	// GetRequiredScopes returns the OAuth scopes needed for posting.
	// These scopes should be requested during the authorization flow.
	GetRequiredScopes() []string
}

// OAuthConfig holds configuration for an OAuth provider.
// This is used to initialize platform-specific providers.
type OAuthConfig struct {
	// ClientID is the OAuth application client ID
	ClientID string

	// ClientSecret is the OAuth application client secret
	ClientSecret string

	// Scopes overrides the default scopes if non-empty
	Scopes []string
}

// AuthProvider constants for platforms with OAuth support
const (
	AuthProviderThreads  = "threads"
	AuthProviderBluesky  = "bluesky" // Uses app passwords, not OAuth
	AuthProviderTwitter  = "twitter"
	AuthProviderLinkedIn = "linkedin"
)

// SupportsOAuth returns true if the platform uses OAuth for authentication
func SupportsOAuth(platform string) bool {
	switch platform {
	case AuthProviderThreads, AuthProviderTwitter, AuthProviderLinkedIn:
		return true
	case AuthProviderBluesky:
		return false // Bluesky uses app passwords
	default:
		return false
	}
}
