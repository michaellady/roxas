package handlers

import (
	"context"
	"net/http"
	"time"
)

// Repository represents a tracked GitHub repository
type Repository struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	GitHubURL     string    `json:"github_url"`
	WebhookSecret string    `json:"webhook_secret"`
	CreatedAt     time.Time `json:"created_at"`
}

// RepositoryStore defines the interface for repository persistence
type RepositoryStore interface {
	CreateRepository(ctx context.Context, userID, githubURL, webhookSecret string) (*Repository, error)
	GetRepositoryByUserAndURL(ctx context.Context, userID, githubURL string) (*Repository, error)
}

// SecretGenerator generates webhook secrets
type SecretGenerator interface {
	Generate() (string, error)
}

// AddRepositoryRequest is the request body for adding a repository
type AddRepositoryRequest struct {
	GitHubURL string `json:"github_url"`
}

// AddRepositoryResponse is the response for adding a repository
type AddRepositoryResponse struct {
	Repository Repository    `json:"repository"`
	Webhook    WebhookConfig `json:"webhook"`
}

// WebhookConfig contains the webhook configuration for the repository
type WebhookConfig struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

// RepositoryHandler handles repository management endpoints
type RepositoryHandler struct {
	store      RepositoryStore
	secretGen  SecretGenerator
	webhookURL string
}

// NewRepositoryHandler creates a new repository handler
func NewRepositoryHandler(store RepositoryStore, secretGen SecretGenerator, webhookURL string) *RepositoryHandler {
	return &RepositoryHandler{
		store:      store,
		secretGen:  secretGen,
		webhookURL: webhookURL,
	}
}

// AddRepository handles POST /api/v1/repositories
// TODO: Implement in TB11 to make tests pass
func (h *RepositoryHandler) AddRepository(w http.ResponseWriter, r *http.Request) {
	// Stub: returns 501 Not Implemented
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error": "not implemented"}`))
}
