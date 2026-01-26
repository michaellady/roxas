package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/mikelady/roxas/internal/services"
)

// GitHub API error definitions
var (
	ErrGitHubRateLimited    = errors.New("rate limited by GitHub API")
	ErrGitHubAuthentication = errors.New("GitHub authentication failed")
	ErrGitHubAPIError       = errors.New("GitHub API error")
)

// GitHubRepo represents a GitHub repository
type GitHubRepo struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	FullName    string    `json:"full_name"`
	Description string    `json:"description"`
	Private     bool      `json:"private"`
	HTMLURL     string    `json:"html_url"`
	CloneURL    string    `json:"clone_url"`
	SSHURL      string    `json:"ssh_url"`
	DefaultBranch string  `json:"default_branch"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	PushedAt    time.Time `json:"pushed_at"`
	Permissions *GitHubRepoPermissions `json:"permissions,omitempty"`
}

// GitHubRepoPermissions represents the authenticated user's permissions on a repo
type GitHubRepoPermissions struct {
	Admin    bool `json:"admin"`
	Maintain bool `json:"maintain"`
	Push     bool `json:"push"`
	Triage   bool `json:"triage"`
	Pull     bool `json:"pull"`
}

// GitHubClient provides access to GitHub API
type GitHubClient struct {
	accessToken string
	baseURL     string
	client      *http.Client
}

// NewGitHubClient creates a new GitHub API client
func NewGitHubClient(accessToken string, baseURL string) *GitHubClient {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}

	return &GitHubClient{
		accessToken: accessToken,
		baseURL:     baseURL,
		client:      &http.Client{Timeout: 30 * time.Second},
	}
}

// Platform returns the platform identifier
func (c *GitHubClient) Platform() string {
	return services.PlatformGitHub
}

// ListUserRepos lists repositories for the authenticated user.
// If adminOnly is true, only repos where user has admin access are returned.
func (c *GitHubClient) ListUserRepos(ctx context.Context, adminOnly bool) ([]GitHubRepo, error) {
	var allRepos []GitHubRepo
	page := 1
	perPage := 100

	for {
		repos, hasMore, err := c.listReposPage(ctx, page, perPage)
		if err != nil {
			return nil, err
		}

		// Filter for admin access if requested
		for _, repo := range repos {
			if adminOnly {
				if repo.Permissions != nil && repo.Permissions.Admin {
					allRepos = append(allRepos, repo)
				}
			} else {
				allRepos = append(allRepos, repo)
			}
		}

		if !hasMore {
			break
		}
		page++
	}

	return allRepos, nil
}

// listReposPage fetches a single page of repositories
func (c *GitHubClient) listReposPage(ctx context.Context, page, perPage int) ([]GitHubRepo, bool, error) {
	params := url.Values{}
	params.Set("page", strconv.Itoa(page))
	params.Set("per_page", strconv.Itoa(perPage))
	params.Set("sort", "updated")
	params.Set("direction", "desc")

	reqURL := fmt.Sprintf("%s/user/repos?%s", c.baseURL, params.Encode())
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("failed to call GitHub API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read response: %w", err)
	}

	// Handle rate limiting
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, false, ErrGitHubRateLimited
	}

	// Handle auth errors
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, false, ErrGitHubAuthentication
	}

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("%w: %d - %s", ErrGitHubAPIError, resp.StatusCode, string(body))
	}

	var repos []GitHubRepo
	if err := json.Unmarshal(body, &repos); err != nil {
		return nil, false, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check if there are more pages
	hasMore := len(repos) == perPage

	return repos, hasMore, nil
}

// GetRepo fetches a single repository by owner and name
func (c *GitHubClient) GetRepo(ctx context.Context, owner, repo string) (*GitHubRepo, error) {
	reqURL := fmt.Sprintf("%s/repos/%s/%s", c.baseURL, owner, repo)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call GitHub API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, ErrGitHubRateLimited
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrGitHubAuthentication
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("repository not found: %s/%s", owner, repo)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d - %s", ErrGitHubAPIError, resp.StatusCode, string(body))
	}

	var result GitHubRepo
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}
