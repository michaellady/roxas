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
var _ services.OAuthProvider = (*GitHubOAuthProvider)(nil)

// GitHubOAuthProvider handles GitHub OAuth 2.0 authentication.
// Uses GitHub's OAuth flow for repository access.
//
// GitHub OAuth Flow:
// 1. Redirect user to authorization URL
// 2. User authorizes, redirected back with code
// 3. Exchange code for access token
// 4. Use access token for API requests
type GitHubOAuthProvider struct {
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	BaseURL      string // For testing; defaults to https://github.com
	APIURL       string // For testing; defaults to https://api.github.com
}

// NewGitHubOAuthProvider creates a new GitHub OAuth provider.
func NewGitHubOAuthProvider(clientID, clientSecret string) *GitHubOAuthProvider {
	return &GitHubOAuthProvider{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		HTTPClient:   &http.Client{Timeout: 30 * time.Second},
		BaseURL:      "https://github.com",
		APIURL:       "https://api.github.com",
	}
}

// Platform returns the platform identifier.
func (p *GitHubOAuthProvider) Platform() string {
	return services.PlatformGitHub
}

// GetAuthURL generates the OAuth authorization URL for GitHub.
// The state parameter prevents CSRF attacks.
func (p *GitHubOAuthProvider) GetAuthURL(state, redirectURL string) string {
	baseURL := p.BaseURL + "/login/oauth/authorize"
	scopes := p.GetRequiredScopes()

	params := url.Values{}
	params.Set("client_id", p.ClientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("scope", strings.Join(scopes, " "))
	params.Set("state", state)

	return baseURL + "?" + params.Encode()
}

// ExchangeCode exchanges an authorization code for OAuth tokens.
func (p *GitHubOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*services.OAuthTokens, error) {
	tokenURL := p.BaseURL + "/login/oauth/access_token"

	data := url.Values{}
	data.Set("client_id", p.ClientID)
	data.Set("client_secret", p.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

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
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("%w: %s", services.ErrCodeExchangeFailed, tokenResp.Error)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("%w: no access token in response", services.ErrCodeExchangeFailed)
	}

	// Get user info to retrieve the GitHub user ID/login
	userID, err := p.getUserID(ctx, tokenResp.AccessToken)
	if err != nil {
		// Don't fail the whole flow if we can't get user ID
		userID = ""
	}

	// GitHub tokens don't expire by default (unless organization settings require it)
	return &services.OAuthTokens{
		AccessToken:    tokenResp.AccessToken,
		PlatformUserID: userID,
		Scopes:         tokenResp.Scope,
		// GitHub personal access tokens don't expire
		ExpiresAt: nil,
	}, nil
}

// getUserID fetches the authenticated user's login from GitHub API.
func (p *GitHubOAuthProvider) getUserID(ctx context.Context, accessToken string) (string, error) {
	userURL := p.APIURL + "/user"

	req, err := http.NewRequestWithContext(ctx, "GET", userURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := p.getHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get user: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var userResp struct {
		Login string `json:"login"`
		ID    int    `json:"id"`
	}

	if err := json.Unmarshal(body, &userResp); err != nil {
		return "", err
	}

	return userResp.Login, nil
}

// RefreshTokens refreshes GitHub access tokens.
// Note: GitHub OAuth tokens don't expire by default, so this returns an error.
// Organizations can configure token expiration, but standard tokens don't need refresh.
func (p *GitHubOAuthProvider) RefreshTokens(ctx context.Context, refreshToken string) (*services.OAuthTokens, error) {
	// GitHub OAuth tokens don't expire by default and don't support refresh
	return nil, services.ErrTokenRefreshFailed
}

// GetRequiredScopes returns the OAuth scopes required for repository access.
func (p *GitHubOAuthProvider) GetRequiredScopes() []string {
	return []string{
		"repo",            // Full control of private repositories
		"admin:repo_hook", // Full control of repository hooks
	}
}

// getHTTPClient returns the HTTP client to use for requests.
func (p *GitHubOAuthProvider) getHTTPClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}
