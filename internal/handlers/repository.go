package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mikelady/roxas/internal/auth"
)

// Repository represents a tracked GitHub repository
type Repository struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	GitHubURL       string    `json:"github_url"`
	WebhookSecret   string    `json:"webhook_secret,omitempty"`
	Name            string    `json:"name"`
	IsActive        bool      `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
	GitHubRepoID    *int64    `json:"github_repo_id,omitempty"`
	WebhookID       *int64    `json:"webhook_id,omitempty"`
	IsPrivate       bool      `json:"is_private"`
	GitHubAppRepoID *string   `json:"github_app_repo_id,omitempty"`
	WebhookSource   string    `json:"webhook_source"`
}

// RepositoryStore defines the interface for repository persistence
type RepositoryStore interface {
	CreateRepository(ctx context.Context, userID, githubURL, webhookSecret string) (*Repository, error)
	GetRepositoryByUserAndURL(ctx context.Context, userID, githubURL string) (*Repository, error)
	ListRepositoriesByUser(ctx context.Context, userID string) ([]*Repository, error)
}

// ErrDuplicateRepository is returned when a user tries to add the same repo twice
var ErrDuplicateRepository = errors.New("repository already exists for this user")

// SecretGenerator generates webhook secrets
type SecretGenerator interface {
	Generate() (string, error)
}

// CryptoSecretGenerator generates secure random secrets using crypto/rand
type CryptoSecretGenerator struct {
	ByteLength int
}

// NewCryptoSecretGenerator creates a new crypto secret generator
func NewCryptoSecretGenerator() *CryptoSecretGenerator {
	return &CryptoSecretGenerator{ByteLength: 32}
}

// Generate creates a cryptographically secure random secret
func (g *CryptoSecretGenerator) Generate() (string, error) {
	bytes := make([]byte, g.ByteLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// ListRepositoriesResponse is the response for listing repositories
type ListRepositoriesResponse struct {
	Repositories []RepositoryResponse `json:"repositories"`
}

// AddRepositoryRequest is the request body for adding a repository
type AddRepositoryRequest struct {
	GitHubURL string `json:"github_url"`
}

// AddRepositoryResponse is the response for adding a repository
type AddRepositoryResponse struct {
	Repository RepositoryResponse `json:"repository"`
	Webhook    WebhookConfig      `json:"webhook"`
}

// RepositoryResponse is the repository object in API responses
type RepositoryResponse struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	GitHubURL string `json:"github_url"`
	CreatedAt string `json:"created_at"`
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

// ListRepositories handles GET /api/v1/repositories
func (h *RepositoryHandler) ListRepositories(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by JWT middleware)
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Get user's repositories
	repos, err := h.store.ListRepositoriesByUser(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to retrieve repositories")
		return
	}

	// Convert to response format (excluding webhook secrets)
	repoResponses := make([]RepositoryResponse, 0, len(repos))
	for _, repo := range repos {
		repoResponses = append(repoResponses, RepositoryResponse{
			ID:        repo.ID,
			UserID:    repo.UserID,
			GitHubURL: repo.GitHubURL,
			CreatedAt: repo.CreatedAt.Format(time.RFC3339),
		})
	}

	resp := ListRepositoriesResponse{
		Repositories: repoResponses,
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// AddRepository handles POST /api/v1/repositories
func (h *RepositoryHandler) AddRepository(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by JWT middleware)
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Parse request body
	var req AddRepositoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate GitHub URL
	if err := validateGitHubURL(req.GitHubURL); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Generate webhook secret
	secret, err := h.secretGen.Generate()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to generate webhook secret")
		return
	}

	// Create repository
	repo, err := h.store.CreateRepository(r.Context(), userID, req.GitHubURL, secret)
	if err != nil {
		if errors.Is(err, ErrDuplicateRepository) {
			h.writeError(w, http.StatusConflict, "repository already exists for this user")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to create repository")
		return
	}

	// Build response
	resp := AddRepositoryResponse{
		Repository: RepositoryResponse{
			ID:        repo.ID,
			UserID:    repo.UserID,
			GitHubURL: repo.GitHubURL,
			CreatedAt: repo.CreatedAt.Format(time.RFC3339),
		},
		Webhook: WebhookConfig{
			URL:    fmt.Sprintf("%s/webhook/%s", h.webhookURL, repo.ID),
			Secret: secret,
		},
	}

	h.writeJSON(w, http.StatusCreated, resp)
}

// validateGitHubURL validates that the URL is a valid GitHub repository URL
func validateGitHubURL(rawURL string) error {
	if rawURL == "" {
		return errors.New("github_url is required")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return errors.New("invalid URL format")
	}

	// Must be HTTPS
	if parsed.Scheme != "https" {
		return errors.New("URL must use HTTPS")
	}

	// Must be github.com
	if parsed.Host != "github.com" {
		return errors.New("URL must be a GitHub repository (github.com)")
	}

	// Path must have at least owner/repo format
	path := strings.Trim(parsed.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return errors.New("URL must be a valid GitHub repository (github.com/owner/repo)")
	}

	return nil
}

func (h *RepositoryHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *RepositoryHandler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, ErrorResponse{Error: message})
}

// GetWebhookConfigForTest returns a webhook configuration for the given repository ID.
// This method is exported for property testing to verify webhook URL and secret format.
func (h *RepositoryHandler) GetWebhookConfigForTest(repoID string) WebhookConfig {
	secret, _ := h.secretGen.Generate()
	return WebhookConfig{
		URL:    fmt.Sprintf("%s/webhook/%s", h.webhookURL, repoID),
		Secret: secret,
	}
}
