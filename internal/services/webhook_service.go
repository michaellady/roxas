package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
)

// =============================================================================
// Webhook Auto-Install Service (alice-61)
// =============================================================================

// Webhook service error definitions
var (
	ErrWebhookCreationFailed    = errors.New("failed to create webhook on GitHub")
	ErrRepositoryNotFound       = errors.New("repository not found on GitHub")
	ErrInsufficientPermissions  = errors.New("insufficient permissions to create webhook")
	ErrGitHubNotFound           = errors.New("resource not found on GitHub")
	ErrGitHubForbidden          = errors.New("insufficient permissions")
	ErrGitHubWebhookExists      = errors.New("webhook already exists for this repository")
)

// WebhookInstallResult contains the result of installing a webhook
type WebhookInstallResult struct {
	RepositoryID string // Our internal repository ID
	GitHubRepoID int64  // GitHub's repository ID
	WebhookID    int64  // GitHub's webhook ID
	Success      bool   // Whether installation succeeded
	Error        error  // Error if installation failed
}

// RepoInstallRequest contains the information needed to install a webhook for a repo
type RepoInstallRequest struct {
	RepositoryID  string // Our internal repository ID
	Owner         string // GitHub owner
	Repo          string // GitHub repo name
	WebhookURL    string // The webhook callback URL
	WebhookSecret string // The webhook secret
}

// GitHubWebhookConfig represents the configuration for creating a webhook
type GitHubWebhookConfig struct {
	URL         string   // The callback URL for the webhook
	Secret      string   // The webhook secret for HMAC validation
	ContentType string   // application/json or application/x-www-form-urlencoded
	Events      []string // Events to subscribe to (e.g., "push", "pull_request")
}

// GitHubWebhook represents a webhook returned from GitHub API
type GitHubWebhook struct {
	ID     int64  // GitHub's webhook ID
	URL    string // GitHub's URL for the webhook resource
	Active bool   // Whether the webhook is active
}

// GitHubRepoInfo represents minimal repository info from GitHub API
type GitHubRepoInfo struct {
	ID        int64  // GitHub's repository ID
	FullName  string // owner/repo format
	IsPrivate bool   // Whether the repo is private
}

// GitHubClientFactory creates GitHub clients with the provided access token
type GitHubClientFactory interface {
	NewClient(accessToken string) GitHubWebhookClient
}

// GitHubWebhookClient defines the interface for GitHub webhook operations
type GitHubWebhookClient interface {
	CreateWebhook(ctx context.Context, owner, repo string, config GitHubWebhookConfig) (*GitHubWebhook, error)
	DeleteWebhook(ctx context.Context, owner, repo string, webhookID int64) error
	GetRepo(ctx context.Context, owner, repo string) (*GitHubRepoInfo, error)
}

// WebhookMetadataStore defines the interface for updating webhook metadata in the repository
type WebhookMetadataStore interface {
	UpdateWebhookID(ctx context.Context, repoID string, webhookID int64) error
	ClearWebhookID(ctx context.Context, repoID string) error
}

// WebhookService handles auto-installation of webhooks via GitHub API
type WebhookService struct {
	clientFactory GitHubClientFactory
	metadataStore WebhookMetadataStore
}

// NewWebhookService creates a new webhook service
func NewWebhookService(clientFactory GitHubClientFactory, metadataStore WebhookMetadataStore) *WebhookService {
	return &WebhookService{
		clientFactory: clientFactory,
		metadataStore: metadataStore,
	}
}

// InstallWebhook installs a webhook on a single GitHub repository
func (s *WebhookService) InstallWebhook(ctx context.Context, accessToken string, req RepoInstallRequest) (*WebhookInstallResult, error) {
	client := s.clientFactory.NewClient(accessToken)

	result := &WebhookInstallResult{
		RepositoryID: req.RepositoryID,
	}

	// Get repository info to get GitHub repo ID
	repoInfo, err := client.GetRepo(ctx, req.Owner, req.Repo)
	if err != nil {
		if errors.Is(err, ErrGitHubNotFound) {
			result.Error = ErrRepositoryNotFound
			return result, ErrRepositoryNotFound
		}
		if errors.Is(err, ErrGitHubForbidden) {
			result.Error = ErrInsufficientPermissions
			return result, ErrInsufficientPermissions
		}
		result.Error = fmt.Errorf("%w: %v", ErrWebhookCreationFailed, err)
		return result, result.Error
	}

	result.GitHubRepoID = repoInfo.ID

	// Create the webhook
	config := GitHubWebhookConfig{
		URL:         req.WebhookURL,
		Secret:      req.WebhookSecret,
		ContentType: "json",
		Events:      []string{"push"},
	}

	webhook, err := client.CreateWebhook(ctx, req.Owner, req.Repo, config)
	if err != nil {
		if errors.Is(err, ErrGitHubWebhookExists) {
			// Webhook already exists - this is OK, try to find it
			result.Error = err
			return result, err
		}
		if errors.Is(err, ErrGitHubForbidden) {
			result.Error = ErrInsufficientPermissions
			return result, ErrInsufficientPermissions
		}
		result.Error = fmt.Errorf("%w: %v", ErrWebhookCreationFailed, err)
		return result, result.Error
	}

	result.WebhookID = webhook.ID

	// Store webhook_id in database
	if s.metadataStore != nil {
		if err := s.metadataStore.UpdateWebhookID(ctx, req.RepositoryID, webhook.ID); err != nil {
			// Cleanup: delete the webhook we just created
			log.Printf("Failed to store webhook_id, cleaning up webhook %d: %v", webhook.ID, err)
			if deleteErr := client.DeleteWebhook(ctx, req.Owner, req.Repo, webhook.ID); deleteErr != nil {
				log.Printf("Failed to cleanup webhook %d after database error: %v", webhook.ID, deleteErr)
			}
			result.Error = fmt.Errorf("failed to store webhook metadata: %w", err)
			return result, result.Error
		}
	}

	result.Success = true
	return result, nil
}

// InstallWebhooksForRepos installs webhooks for multiple repositories
// Returns results for all repos, even if some fail (partial success)
func (s *WebhookService) InstallWebhooksForRepos(ctx context.Context, accessToken string, requests []RepoInstallRequest) []WebhookInstallResult {
	results := make([]WebhookInstallResult, 0, len(requests))

	for _, req := range requests {
		result, _ := s.InstallWebhook(ctx, accessToken, req)
		results = append(results, *result)
	}

	return results
}

// UninstallWebhook removes a webhook from a GitHub repository
func (s *WebhookService) UninstallWebhook(ctx context.Context, accessToken string, owner, repo string, webhookID int64, repoID string) error {
	client := s.clientFactory.NewClient(accessToken)

	// Delete from GitHub
	if err := client.DeleteWebhook(ctx, owner, repo, webhookID); err != nil {
		// If webhook is already gone, that's fine
		if !errors.Is(err, ErrGitHubNotFound) {
			return fmt.Errorf("failed to delete webhook: %w", err)
		}
	}

	// Clear webhook_id in database
	if s.metadataStore != nil && repoID != "" {
		if err := s.metadataStore.ClearWebhookID(ctx, repoID); err != nil {
			return fmt.Errorf("failed to clear webhook metadata: %w", err)
		}
	}

	return nil
}

// ParseGitHubURL extracts owner and repo from a GitHub URL
// Accepts formats: https://github.com/owner/repo or https://github.com/owner/repo.git
func ParseGitHubURL(githubURL string) (owner, repo string, err error) {
	// Remove trailing .git if present
	githubURL = strings.TrimSuffix(githubURL, ".git")

	// Remove https://github.com/ prefix
	if !strings.HasPrefix(githubURL, "https://github.com/") {
		return "", "", fmt.Errorf("invalid GitHub URL: must start with https://github.com/")
	}

	path := strings.TrimPrefix(githubURL, "https://github.com/")
	parts := strings.Split(path, "/")

	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid GitHub URL: must be in format https://github.com/owner/repo")
	}

	return parts[0], parts[1], nil
}

