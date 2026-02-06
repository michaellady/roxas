package clients

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GitHubAppClient handles GitHub App authentication and API calls.
type GitHubAppClient struct {
	appID      int64
	privateKey *rsa.PrivateKey
	baseURL    string
	client     *http.Client
}

// InstallationInfo represents a GitHub App installation
type InstallationInfo struct {
	ID      int64  `json:"id"`
	Account struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
		Type  string `json:"type"` // "User" or "Organization"
	} `json:"account"`
	AppID       int64      `json:"app_id"`
	SuspendedAt *time.Time `json:"suspended_at"`
	SuspendedBy *struct {
		Login string `json:"login"`
	} `json:"suspended_by"`
}

// InstallationToken represents an installation access token
type InstallationToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// InstallationRepo represents a repository accessible to an installation
type InstallationRepo struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	HTMLURL       string `json:"html_url"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
}

// NewGitHubAppClient creates a new GitHub App client.
// privateKeyPEM is the PEM-encoded RSA private key from the GitHub App settings.
func NewGitHubAppClient(appID int64, privateKeyPEM []byte, baseURL string) (*GitHubAppClient, error) {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &GitHubAppClient{
		appID:      appID,
		privateKey: key,
		baseURL:    baseURL,
		client:     &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// CreateJWT creates a signed JWT for GitHub App authentication.
// The JWT is valid for 10 minutes (GitHub's maximum).
func (c *GitHubAppClient) CreateJWT() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)), // 60s clock drift
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		Issuer:    fmt.Sprintf("%d", c.appID),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(c.privateKey)
}

// CreateInstallationToken creates an installation access token.
// These tokens expire after 1 hour and should NOT be stored.
func (c *GitHubAppClient) CreateInstallationToken(ctx context.Context, installationID int64) (*InstallationToken, error) {
	jwtToken, err := c.CreateJWT()
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", c.baseURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create installation token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(body))
	}

	var token InstallationToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &token, nil
}

// GetInstallation retrieves installation details from GitHub.
func (c *GitHubAppClient) GetInstallation(ctx context.Context, installationID int64) (*InstallationInfo, error) {
	jwtToken, err := c.CreateJWT()
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d", c.baseURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get installation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(body))
	}

	var info InstallationInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode installation: %w", err)
	}

	return &info, nil
}

// ListInstallationRepos lists repositories accessible to an installation.
// Uses an installation token (not the app JWT).
func (c *GitHubAppClient) ListInstallationRepos(ctx context.Context, installationID int64) ([]InstallationRepo, error) {
	token, err := c.CreateInstallationToken(ctx, installationID)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/installation/repositories", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+token.Token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list repos: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Repositories []InstallationRepo `json:"repositories"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode repos: %w", err)
	}

	return result.Repositories, nil
}
