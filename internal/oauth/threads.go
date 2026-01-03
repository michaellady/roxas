package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mikelady/roxas/internal/services"
)

// Compile-time interface compliance check
var _ services.OAuthProvider = (*ThreadsOAuthProvider)(nil)

// ThreadsOAuthProvider handles Meta Threads OAuth 2.0 authentication.
// Uses Meta's OAuth flow with Threads-specific endpoints.
//
// Threads OAuth Flow:
// 1. Redirect user to authorization URL
// 2. User authorizes, redirected back with code
// 3. Exchange code for short-lived token (1 hour)
// 4. Exchange short-lived token for long-lived token (60 days)
// 5. Refresh long-lived token before expiration
type ThreadsOAuthProvider struct {
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	BaseURL      string // For testing; defaults to https://graph.threads.net
}

// NewThreadsOAuthProvider creates a new Threads OAuth provider.
func NewThreadsOAuthProvider(clientID, clientSecret string) *ThreadsOAuthProvider {
	return &ThreadsOAuthProvider{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		HTTPClient:   &http.Client{Timeout: 30 * time.Second},
		BaseURL:      "https://graph.threads.net",
	}
}

// Platform returns the platform identifier.
func (p *ThreadsOAuthProvider) Platform() string {
	return services.PlatformThreads
}

// GetAuthURL generates the OAuth authorization URL for Threads.
// The state parameter prevents CSRF attacks.
func (p *ThreadsOAuthProvider) GetAuthURL(state, redirectURL string) string {
	baseURL := "https://www.threads.net/oauth/authorize"
	scopes := p.GetRequiredScopes()

	params := url.Values{}
	params.Set("client_id", p.ClientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("scope", strings.Join(scopes, ","))
	params.Set("response_type", "code")
	params.Set("state", state)

	return baseURL + "?" + params.Encode()
}

// ExchangeCode exchanges an authorization code for OAuth tokens.
// Threads returns a short-lived token which is then exchanged for a long-lived token.
func (p *ThreadsOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*services.OAuthTokens, error) {
	// Step 1: Exchange code for short-lived token
	shortLivedToken, err := p.exchangeCodeForToken(ctx, code, redirectURL)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Step 2: Exchange short-lived token for long-lived token
	longLivedToken, err := p.exchangeForLongLivedToken(ctx, shortLivedToken.AccessToken)
	if err != nil {
		// Return short-lived token if long-lived exchange fails
		// The caller can still use it, just with shorter expiration
		return shortLivedToken, nil
	}

	return longLivedToken, nil
}

// exchangeCodeForToken exchanges the authorization code for a short-lived access token.
func (p *ThreadsOAuthProvider) exchangeCodeForToken(ctx context.Context, code, redirectURL string) (*services.OAuthTokens, error) {
	tokenURL := p.BaseURL + "/oauth/access_token"

	data := url.Values{}
	data.Set("client_id", p.ClientID)
	data.Set("client_secret", p.ClientSecret)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", redirectURL)
	data.Set("code", code)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.getHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%w: %s - %s", services.ErrCodeExchangeFailed, errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("%w: status %d", services.ErrCodeExchangeFailed, resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		UserID      string `json:"user_id"`
		// Short-lived tokens expire in 1 hour (3600 seconds)
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Short-lived tokens expire in 1 hour
	expiresAt := time.Now().Add(1 * time.Hour)

	return &services.OAuthTokens{
		AccessToken:    tokenResp.AccessToken,
		PlatformUserID: tokenResp.UserID,
		ExpiresAt:      &expiresAt,
		Scopes:         strings.Join(p.GetRequiredScopes(), " "),
	}, nil
}

// exchangeForLongLivedToken exchanges a short-lived token for a long-lived token.
// Long-lived tokens are valid for 60 days and can be refreshed.
func (p *ThreadsOAuthProvider) exchangeForLongLivedToken(ctx context.Context, shortLivedToken string) (*services.OAuthTokens, error) {
	tokenURL := p.BaseURL + "/access_token"

	params := url.Values{}
	params.Set("grant_type", "th_exchange_token")
	params.Set("client_secret", p.ClientSecret)
	params.Set("access_token", shortLivedToken)

	req, err := http.NewRequestWithContext(ctx, "GET", tokenURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.getHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("long-lived token exchange failed: status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"` // Seconds until expiration (typically 5184000 = 60 days)
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return &services.OAuthTokens{
		AccessToken: tokenResp.AccessToken,
		ExpiresAt:   &expiresAt,
		Scopes:      strings.Join(p.GetRequiredScopes(), " "),
		// Note: Threads long-lived tokens don't have a refresh token
		// They are refreshed by calling the refresh endpoint with the token itself
	}, nil
}

// RefreshTokens refreshes a long-lived Threads access token.
// The "refreshToken" parameter is actually the long-lived access token itself,
// as Threads uses the access token for refresh operations.
func (p *ThreadsOAuthProvider) RefreshTokens(ctx context.Context, refreshToken string) (*services.OAuthTokens, error) {
	tokenURL := p.BaseURL + "/refresh_access_token"

	params := url.Values{}
	params.Set("grant_type", "th_refresh_token")
	params.Set("access_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, "GET", tokenURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.getHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%w: %s - %s", services.ErrTokenRefreshFailed, errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("%w: status %d", services.ErrTokenRefreshFailed, resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse refresh response: %w", err)
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return &services.OAuthTokens{
		AccessToken: tokenResp.AccessToken,
		ExpiresAt:   &expiresAt,
		Scopes:      strings.Join(p.GetRequiredScopes(), " "),
	}, nil
}

// GetRequiredScopes returns the OAuth scopes required for Threads posting.
func (p *ThreadsOAuthProvider) GetRequiredScopes() []string {
	return []string{
		"threads_basic",           // Basic profile access
		"threads_content_publish", // Ability to publish posts
		"threads_manage_insights", // Access to rate limit info
	}
}

// getHTTPClient returns the HTTP client to use for requests.
func (p *ThreadsOAuthProvider) getHTTPClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}
