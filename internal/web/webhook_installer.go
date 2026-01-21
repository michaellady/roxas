package web

import (
	"context"
	"fmt"

	"github.com/mikelady/roxas/internal/services"
)

// WebhookInstallerAdapter adapts the services.WebhookService to the WebhookInstaller interface
type WebhookInstallerAdapter struct {
	webhookService        *services.WebhookService
	gitHubCredentialStore GitHubCredentialStore
}

// NewWebhookInstallerAdapter creates a new webhook installer adapter
func NewWebhookInstallerAdapter(webhookService *services.WebhookService, credStore GitHubCredentialStore) *WebhookInstallerAdapter {
	return &WebhookInstallerAdapter{
		webhookService:        webhookService,
		gitHubCredentialStore: credStore,
	}
}

// InstallWebhookForRepo attempts to auto-install a webhook for a repository
func (a *WebhookInstallerAdapter) InstallWebhookForRepo(ctx context.Context, userID, repoID, githubURL, webhookURL, webhookSecret string) (*WebhookInstallResult, error) {
	// Get GitHub access token for the user
	accessToken, err := a.gitHubCredentialStore.GetGitHubAccessToken(ctx, userID)
	if err != nil || accessToken == "" {
		// User doesn't have GitHub OAuth connected - this is not an error
		return &WebhookInstallResult{
			Success:      false,
			ErrorMessage: "GitHub not connected",
		}, nil
	}

	// Parse GitHub URL to extract owner and repo
	owner, repo, err := services.ParseGitHubURL(githubURL)
	if err != nil {
		return &WebhookInstallResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Invalid GitHub URL: %v", err),
		}, nil
	}

	// Install the webhook
	result, err := a.webhookService.InstallWebhook(ctx, accessToken, services.RepoInstallRequest{
		RepositoryID:  repoID,
		Owner:         owner,
		Repo:          repo,
		WebhookURL:    webhookURL,
		WebhookSecret: webhookSecret,
	})

	if err != nil {
		return &WebhookInstallResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Webhook install failed: %v", err),
		}, nil
	}

	return &WebhookInstallResult{
		WebhookID:    result.WebhookID,
		Success:      result.Success,
		ErrorMessage: "",
	}, nil
}
