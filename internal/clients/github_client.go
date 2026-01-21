package clients

import (
	"context"
	"errors"
)

// TDD RED PHASE STUB - Implementation pending alice-82

var (
	ErrGitHubRateLimited    = errors.New("github: rate limited")
	ErrGitHubAuthentication = errors.New("github: authentication failed")
	ErrGitHubAPIError       = errors.New("github: API error")
)

// GitHubRepoPermissions represents permissions for a GitHub repository
type GitHubRepoPermissions struct {
	Admin bool
	Push  bool
	Pull  bool
}

// GitHubRepo represents a GitHub repository
type GitHubRepo struct {
	ID          int64
	Name        string
	FullName    string
	HTMLURL     string
	Private     bool
	Admin       bool
	Push        bool
	Pull        bool
	Description string
	Permissions GitHubRepoPermissions
}

// GitHubClient is a client for GitHub API
type GitHubClient struct {
	token   string
	baseURL string
}

// ListUserReposOption is a functional option for ListUserRepos
type ListUserReposOption func(*listReposConfig)

type listReposConfig struct {
	adminOnly bool
}

// WithAdminOnly filters repos to only those where user has admin access
func WithAdminOnly(adminOnly bool) ListUserReposOption {
	return func(c *listReposConfig) {
		c.adminOnly = adminOnly
	}
}

// NewGitHubClient creates a new GitHub client
func NewGitHubClient(token, baseURL string) *GitHubClient {
	return &GitHubClient{
		token:   token,
		baseURL: baseURL,
	}
}

// ListUserRepos lists repositories for the authenticated user
// TDD RED PHASE - Implementation pending
func (c *GitHubClient) ListUserRepos(ctx context.Context, opts ...ListUserReposOption) ([]*GitHubRepo, error) {
	// TODO: Implement - this is TDD red phase stub
	return nil, errors.New("not implemented: TDD red phase")
}
