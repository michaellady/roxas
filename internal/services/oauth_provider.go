package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// =============================================================================
// OAuthProvider Interface and Types
// Platform-specific OAuth authentication providers
// =============================================================================

// OAuth error definitions
var (
	ErrInvalidState       = errors.New("invalid OAuth state parameter")
	ErrCodeExchangeFailed = errors.New("failed to exchange authorization code")
	ErrTokenRefreshFailed = errors.New("failed to refresh tokens")
	ErrInvalidCredentials = errors.New("invalid OAuth credentials")
	ErrScopesInsufficient = errors.New("insufficient OAuth scopes granted")
)

// OAuthTokens represents the tokens returned from OAuth authentication.
// Used by OAuthProvider implementations to return authentication results.
type OAuthTokens struct {
	// AccessToken is the OAuth access token for API requests.
	AccessToken string

	// RefreshToken is the OAuth refresh token for obtaining new access tokens.
	// May be empty if the platform doesn't support refresh tokens.
	RefreshToken string

	// ExpiresAt is when the access token expires.
	// May be nil if the token doesn't expire.
	ExpiresAt *time.Time

	// PlatformUserID is the user's ID on the platform (e.g., Twitter handle, LinkedIn URN).
	PlatformUserID string

	// Scopes is a space-separated list of granted OAuth scopes.
	Scopes string
}

// IsExpired returns true if the access token has expired.
func (t *OAuthTokens) IsExpired() bool {
	if t.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*t.ExpiresAt)
}

// HasRefreshToken returns true if a refresh token is available.
func (t *OAuthTokens) HasRefreshToken() bool {
	return t.RefreshToken != ""
}

// OAuthProvider defines the interface for platform-specific OAuth authentication.
// Each platform (Threads, Twitter, LinkedIn, etc.) implements this interface
// to handle their specific OAuth flow requirements.
type OAuthProvider interface {
	// Platform returns the platform identifier (e.g., "threads", "twitter").
	// Use the Platform* constants defined in post_generator.go and credential_store.go.
	Platform() string

	// GetAuthURL generates the OAuth authorization URL for the platform.
	// The state parameter should be a cryptographically secure random string
	// to prevent CSRF attacks. The redirectURL is where the platform will
	// redirect after authorization.
	GetAuthURL(state, redirectURL string) string

	// ExchangeCode exchanges an authorization code for OAuth tokens.
	// Called after the user authorizes the application and the platform
	// redirects back with an authorization code.
	ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error)

	// RefreshTokens uses a refresh token to obtain new access tokens.
	// Returns ErrTokenRefreshFailed if refresh fails.
	// Some platforms (like Bluesky with app passwords) may not support refresh.
	RefreshTokens(ctx context.Context, refreshToken string) (*OAuthTokens, error)

	// GetRequiredScopes returns the OAuth scopes required for posting.
	// These scopes should be included in the authorization request.
	GetRequiredScopes() []string
}

// =============================================================================
// Platform OAuth Provider Stubs
// These are placeholder implementations to be filled in with actual OAuth logic.
// =============================================================================

// ThreadsOAuthProvider handles Meta Threads OAuth 2.0 authentication.
// Uses Meta's OAuth flow with Instagram Business/Creator account linking.
type ThreadsOAuthProvider struct {
	ClientID     string
	ClientSecret string
}

func (p *ThreadsOAuthProvider) Platform() string {
	return PlatformThreads
}

func (p *ThreadsOAuthProvider) GetAuthURL(state, redirectURL string) string {
	// Meta OAuth URL for Threads
	// See: https://developers.facebook.com/docs/threads/get-started
	baseURL := "https://www.threads.net/oauth/authorize"
	scopes := p.GetRequiredScopes()
	return baseURL + "?client_id=" + p.ClientID +
		"&redirect_uri=" + redirectURL +
		"&scope=" + joinScopes(scopes) +
		"&response_type=code" +
		"&state=" + state
}

func (p *ThreadsOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error) {
	// TODO: Implement actual Meta OAuth token exchange
	// POST to https://graph.threads.net/oauth/access_token
	return nil, ErrCodeExchangeFailed
}

func (p *ThreadsOAuthProvider) RefreshTokens(ctx context.Context, refreshToken string) (*OAuthTokens, error) {
	// TODO: Implement Meta token refresh
	// GET https://graph.threads.net/refresh_access_token
	return nil, ErrTokenRefreshFailed
}

func (p *ThreadsOAuthProvider) GetRequiredScopes() []string {
	return []string{
		"threads_basic",
		"threads_content_publish",
	}
}

// BlueskyAuthProvider handles Bluesky authentication via app passwords.
// Bluesky uses AT Protocol with app passwords instead of OAuth.
//
// Auth Flow:
// 1. User creates an app password at https://bsky.app/settings/app-passwords
// 2. User enters handle + app password in the application
// 3. Application calls createSession to get JWT tokens
// 4. JWT tokens are stored and used for API requests
type BlueskyAuthProvider struct {
	// PDSURL is the Personal Data Server URL. Defaults to https://bsky.social
	PDSURL string

	// Client is the HTTP client to use. If nil, a default client is created.
	Client *http.Client
}

// Default Bluesky PDS URL
const DefaultBlueskyPDSURL = "https://bsky.social"

func (p *BlueskyAuthProvider) Platform() string {
	return PlatformBluesky
}

func (p *BlueskyAuthProvider) GetAuthURL(state, redirectURL string) string {
	// Bluesky doesn't use OAuth - users create app passwords directly
	// Return a help URL or instruction page
	return "https://bsky.app/settings/app-passwords?state=" + state + "&redirect_uri=" + redirectURL
}

// ExchangeCode authenticates with Bluesky using an app password.
// For Bluesky, the "code" parameter should be formatted as "handle:appPassword".
// The redirectURL parameter is ignored for Bluesky.
func (p *BlueskyAuthProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error) {
	// Parse credentials from the code parameter
	handle, password, err := parseBlueskyCredentials(code)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCredentials, err)
	}

	// Normalize the handle
	handle = normalizeBlueskyHandle(handle)

	// Get the PDS URL
	pdsURL := p.PDSURL
	if pdsURL == "" {
		pdsURL = DefaultBlueskyPDSURL
	}

	// Get HTTP client
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	// Create session request
	reqBody := blueskyCreateSessionRequest{
		Identifier: handle,
		Password:   password,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := pdsURL + "/xrpc/com.atproto.server.createSession"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call createSession: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrInvalidCredentials
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d - %s", ErrCodeExchangeFailed, resp.StatusCode, string(body))
	}

	var sessionResp blueskySessionResponse
	if err := json.Unmarshal(body, &sessionResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &OAuthTokens{
		AccessToken:    sessionResp.AccessJwt,
		RefreshToken:   sessionResp.RefreshJwt,
		PlatformUserID: sessionResp.DID,
		Scopes:         "atproto",
		// Bluesky access tokens typically expire in 2 hours
		ExpiresAt: oauthExpiryPtr(time.Now().Add(2 * time.Hour)),
	}, nil
}

// RefreshTokens refreshes Bluesky session tokens.
// Unlike traditional OAuth, Bluesky uses JWT refresh via the refreshSession endpoint.
func (p *BlueskyAuthProvider) RefreshTokens(ctx context.Context, refreshToken string) (*OAuthTokens, error) {
	// Get the PDS URL
	pdsURL := p.PDSURL
	if pdsURL == "" {
		pdsURL = DefaultBlueskyPDSURL
	}

	// Get HTTP client
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	url := pdsURL + "/xrpc/com.atproto.server.refreshSession"
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+refreshToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call refreshSession: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrTokenRefreshFailed
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d - %s", ErrTokenRefreshFailed, resp.StatusCode, string(body))
	}

	var sessionResp blueskySessionResponse
	if err := json.Unmarshal(body, &sessionResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &OAuthTokens{
		AccessToken:    sessionResp.AccessJwt,
		RefreshToken:   sessionResp.RefreshJwt,
		PlatformUserID: sessionResp.DID,
		Scopes:         "atproto",
		ExpiresAt:      oauthExpiryPtr(time.Now().Add(2 * time.Hour)),
	}, nil
}

func (p *BlueskyAuthProvider) GetRequiredScopes() []string {
	// Bluesky doesn't use scopes - app passwords have full access
	return []string{"atproto"}
}

// blueskyCreateSessionRequest is the request body for createSession
type blueskyCreateSessionRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

// blueskySessionResponse is the response from createSession and refreshSession
type blueskySessionResponse struct {
	AccessJwt  string `json:"accessJwt"`
	RefreshJwt string `json:"refreshJwt"`
	Handle     string `json:"handle"`
	DID        string `json:"did"`
}

// parseBlueskyCredentials parses "handle:password" format credentials
func parseBlueskyCredentials(code string) (handle, password string, err error) {
	if code == "" {
		return "", "", fmt.Errorf("empty credentials")
	}

	idx := strings.Index(code, ":")
	if idx == -1 {
		return "", "", fmt.Errorf("invalid format: expected 'handle:password'")
	}

	handle = code[:idx]
	password = code[idx+1:]

	if handle == "" || password == "" {
		return "", "", fmt.Errorf("handle and password are required")
	}

	return handle, password, nil
}

// normalizeBlueskyHandle normalizes a Bluesky handle.
// - Strips leading @ if present
// - Adds .bsky.social suffix if no domain present
func normalizeBlueskyHandle(handle string) string {
	// Strip leading @
	handle = strings.TrimPrefix(handle, "@")

	// If handle doesn't contain a dot, add .bsky.social
	if !strings.Contains(handle, ".") {
		handle = handle + ".bsky.social"
	}

	return handle
}

// oauthExpiryPtr returns a pointer to a time value
func oauthExpiryPtr(t time.Time) *time.Time {
	return &t
}

// TwitterOAuthProvider handles Twitter/X OAuth 2.0 authentication.
type TwitterOAuthProvider struct {
	ClientID     string
	ClientSecret string
}

func (p *TwitterOAuthProvider) Platform() string {
	return PlatformTwitter
}

func (p *TwitterOAuthProvider) GetAuthURL(state, redirectURL string) string {
	// Twitter OAuth 2.0 with PKCE
	// See: https://developer.twitter.com/en/docs/authentication/oauth-2-0/authorization-code
	baseURL := "https://twitter.com/i/oauth2/authorize"
	scopes := p.GetRequiredScopes()
	return baseURL + "?client_id=" + p.ClientID +
		"&redirect_uri=" + redirectURL +
		"&scope=" + joinScopes(scopes) +
		"&response_type=code" +
		"&state=" + state +
		"&code_challenge_method=S256" +
		"&code_challenge=placeholder" // TODO: Generate proper PKCE challenge
}

func (p *TwitterOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error) {
	// TODO: Implement Twitter OAuth token exchange with PKCE
	// POST to https://api.twitter.com/2/oauth2/token
	return nil, ErrCodeExchangeFailed
}

func (p *TwitterOAuthProvider) RefreshTokens(ctx context.Context, refreshToken string) (*OAuthTokens, error) {
	// TODO: Implement Twitter token refresh
	// POST to https://api.twitter.com/2/oauth2/token with grant_type=refresh_token
	return nil, ErrTokenRefreshFailed
}

func (p *TwitterOAuthProvider) GetRequiredScopes() []string {
	return []string{
		"tweet.read",
		"tweet.write",
		"users.read",
		"offline.access", // For refresh tokens
	}
}

// LinkedInOAuthProvider handles LinkedIn OAuth 2.0 authentication.
type LinkedInOAuthProvider struct {
	ClientID     string
	ClientSecret string
}

func (p *LinkedInOAuthProvider) Platform() string {
	return PlatformLinkedIn
}

func (p *LinkedInOAuthProvider) GetAuthURL(state, redirectURL string) string {
	// LinkedIn OAuth 2.0
	// See: https://learn.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow
	baseURL := "https://www.linkedin.com/oauth/v2/authorization"
	scopes := p.GetRequiredScopes()
	return baseURL + "?client_id=" + p.ClientID +
		"&redirect_uri=" + redirectURL +
		"&scope=" + joinScopes(scopes) +
		"&response_type=code" +
		"&state=" + state
}

func (p *LinkedInOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error) {
	// TODO: Implement LinkedIn OAuth token exchange
	// POST to https://www.linkedin.com/oauth/v2/accessToken
	return nil, ErrCodeExchangeFailed
}

func (p *LinkedInOAuthProvider) RefreshTokens(ctx context.Context, refreshToken string) (*OAuthTokens, error) {
	// TODO: Implement LinkedIn token refresh
	// POST to https://www.linkedin.com/oauth/v2/accessToken with grant_type=refresh_token
	return nil, ErrTokenRefreshFailed
}

func (p *LinkedInOAuthProvider) GetRequiredScopes() []string {
	return []string{
		"openid",
		"profile",
		"w_member_social", // For posting
	}
}

// =============================================================================
// Helper functions
// =============================================================================

// joinScopes joins scope strings with space separator for OAuth URL.
func joinScopes(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}

// Compile-time interface compliance checks
var (
	_ OAuthProvider = (*ThreadsOAuthProvider)(nil)
	_ OAuthProvider = (*BlueskyAuthProvider)(nil)
	_ OAuthProvider = (*TwitterOAuthProvider)(nil)
	_ OAuthProvider = (*LinkedInOAuthProvider)(nil)
)
