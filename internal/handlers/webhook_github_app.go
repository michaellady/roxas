package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// =============================================================================
// GitHub App Webhook Handler
// =============================================================================

// InstallationStoreInterface defines the interface for installation persistence
type InstallationStoreInterface interface {
	UpsertInstallation(ctx context.Context, inst *InstallationRecord) (*InstallationRecord, error)
	DeleteInstallation(ctx context.Context, installationID int64) error
	SuspendInstallation(ctx context.Context, installationID int64) error
	UnsuspendInstallation(ctx context.Context, installationID int64) error
	GetInstallationByID(ctx context.Context, installationID int64) (*InstallationRecord, error)
}

// AppRepositoryStoreInterface defines the interface for app repository persistence
type AppRepositoryStoreInterface interface {
	UpsertAppRepository(ctx context.Context, repo *AppRepositoryRecord) (*AppRepositoryRecord, error)
	RemoveAppRepository(ctx context.Context, installationID, githubRepoID int64) error
	GetByGitHubRepoID(ctx context.Context, githubRepoID int64) (*AppRepositoryRecord, error)
}

// GitHubAppRepoStore extends WebhookRepositoryStore with app-repo lookup
type GitHubAppRepoStore interface {
	GetRepositoryByID(ctx context.Context, repoID string) (*Repository, error)
	GetRepositoryByAppRepoID(ctx context.Context, appRepoID string) (*Repository, error)
}

// =============================================================================
// Payload types
// =============================================================================

// GitHubAppInstallationPayload represents the installation event payload
type GitHubAppInstallationPayload struct {
	Action       string `json:"action"`
	Installation struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
			ID    int64  `json:"id"`
			Type  string `json:"type"`
		} `json:"account"`
	} `json:"installation"`
	Sender struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	} `json:"sender"`
	Repositories []GitHubAppRepoPayload `json:"repositories"`
}

// GitHubAppInstallationReposPayload represents the installation_repositories event payload
type GitHubAppInstallationReposPayload struct {
	Action       string `json:"action"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
	RepositoriesAdded   []GitHubAppRepoPayload `json:"repositories_added"`
	RepositoriesRemoved []GitHubAppRepoPayload `json:"repositories_removed"`
}

// GitHubAppRepoPayload represents a repository in GitHub App webhook payloads
type GitHubAppRepoPayload struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	HTMLURL       string `json:"html_url,omitempty"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch,omitempty"`
}

// GitHubAppPushPayload represents a push event from a GitHub App webhook
type GitHubAppPushPayload struct {
	Ref          string `json:"ref"`
	Before       string `json:"before"`
	After        string `json:"after"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
	Repository struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`
	Commits []GitHubCommit `json:"commits"`
}

// =============================================================================
// Response type
// =============================================================================

// GitHubAppWebhookResponse is the JSON response for GitHub App webhook requests
type GitHubAppWebhookResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	DraftID string `json:"draft_id,omitempty"`
}

// =============================================================================
// Handler
// =============================================================================

// GitHubAppWebhookHandler handles GitHub App webhook events
type GitHubAppWebhookHandler struct {
	webhookSecret     string
	installationStore InstallationStoreInterface
	appRepoStore      AppRepositoryStoreInterface
	repoStore         GitHubAppRepoStore
	draftStore        DraftWebhookStore
	idempotencyStore  IdempotencyStore
	activityStore     ActivityStore      // optional
	aiGenerator       AIGeneratorService // optional
}

// NewGitHubAppWebhookHandler creates a new GitHub App webhook handler
func NewGitHubAppWebhookHandler(
	webhookSecret string,
	installationStore InstallationStoreInterface,
	appRepoStore AppRepositoryStoreInterface,
	repoStore GitHubAppRepoStore,
	draftStore DraftWebhookStore,
	idempotencyStore IdempotencyStore,
) *GitHubAppWebhookHandler {
	return &GitHubAppWebhookHandler{
		webhookSecret:     webhookSecret,
		installationStore: installationStore,
		appRepoStore:      appRepoStore,
		repoStore:         repoStore,
		draftStore:        draftStore,
		idempotencyStore:  idempotencyStore,
	}
}

// WithActivityStore adds an activity store for logging
func (h *GitHubAppWebhookHandler) WithActivityStore(store ActivityStore) *GitHubAppWebhookHandler {
	h.activityStore = store
	return h
}

// WithAIGenerator adds an AI generator service
func (h *GitHubAppWebhookHandler) WithAIGenerator(gen AIGeneratorService) *GitHubAppWebhookHandler {
	h.aiGenerator = gen
	return h
}

// ServeHTTP implements http.Handler for GitHubAppWebhookHandler
func (h *GitHubAppWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to read request body")
		return
	}
	defer r.Body.Close()

	// Validate GitHub signature
	signature := r.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		h.writeError(w, http.StatusUnauthorized, "missing signature")
		return
	}

	if !h.validateSignature(body, signature, h.webhookSecret) {
		h.writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	// Route by event type
	eventType := r.Header.Get("X-GitHub-Event")
	switch eventType {
	case "ping":
		h.handlePing(w)
	case "installation":
		h.handleInstallation(r.Context(), w, body)
	case "installation_repositories":
		h.handleInstallationRepositories(r.Context(), w, body)
	case "push":
		h.handlePush(r, w, body)
	default:
		// Unknown event type - acknowledge but ignore
		h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "event acknowledged"})
	}
}

// =============================================================================
// Event handlers
// =============================================================================

func (h *GitHubAppWebhookHandler) handlePing(w http.ResponseWriter) {
	h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "pong"})
}

func (h *GitHubAppWebhookHandler) handleInstallation(ctx context.Context, w http.ResponseWriter, body []byte) {
	var payload GitHubAppInstallationPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	switch payload.Action {
	case "created":
		inst := &InstallationRecord{
			InstallationID: payload.Installation.ID,
			AccountLogin:   payload.Installation.Account.Login,
			AccountID:      payload.Installation.Account.ID,
			AccountType:    payload.Installation.Account.Type,
		}
		if _, err := h.installationStore.UpsertInstallation(ctx, inst); err != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to store installation")
			return
		}

		// Also upsert any repositories included in the installation event
		for _, repo := range payload.Repositories {
			appRepo := &AppRepositoryRecord{
				InstallationID: payload.Installation.ID,
				GitHubRepoID:   repo.ID,
				FullName:       repo.FullName,
				HTMLURL:        repo.HTMLURL,
				Private:        repo.Private,
				DefaultBranch:  repo.DefaultBranch,
				IsActive:       true,
			}
			if _, err := h.appRepoStore.UpsertAppRepository(ctx, appRepo); err != nil {
				log.Printf("failed to upsert app repo %s during installation: %v", repo.FullName, err)
			}
		}

		h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "installation created"})

	case "deleted":
		if err := h.installationStore.DeleteInstallation(ctx, payload.Installation.ID); err != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to delete installation")
			return
		}
		h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "installation deleted"})

	case "suspend":
		if err := h.installationStore.SuspendInstallation(ctx, payload.Installation.ID); err != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to suspend installation")
			return
		}
		h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "installation suspended"})

	case "unsuspend":
		if err := h.installationStore.UnsuspendInstallation(ctx, payload.Installation.ID); err != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to unsuspend installation")
			return
		}
		h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "installation unsuspended"})

	default:
		h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "action acknowledged"})
	}
}

func (h *GitHubAppWebhookHandler) handleInstallationRepositories(ctx context.Context, w http.ResponseWriter, body []byte) {
	var payload GitHubAppInstallationReposPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	switch payload.Action {
	case "added":
		for _, repo := range payload.RepositoriesAdded {
			appRepo := &AppRepositoryRecord{
				InstallationID: payload.Installation.ID,
				GitHubRepoID:   repo.ID,
				FullName:       repo.FullName,
				HTMLURL:        repo.HTMLURL,
				Private:        repo.Private,
				DefaultBranch:  repo.DefaultBranch,
				IsActive:       true,
			}
			if _, err := h.appRepoStore.UpsertAppRepository(ctx, appRepo); err != nil {
				log.Printf("failed to upsert app repo %s: %v", repo.FullName, err)
			}
		}
		h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "repositories added"})

	case "removed":
		for _, repo := range payload.RepositoriesRemoved {
			if err := h.appRepoStore.RemoveAppRepository(ctx, payload.Installation.ID, repo.ID); err != nil {
				log.Printf("failed to remove app repo %d: %v", repo.ID, err)
			}
		}
		h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "repositories removed"})

	default:
		h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "action acknowledged"})
	}
}

func (h *GitHubAppWebhookHandler) handlePush(r *http.Request, w http.ResponseWriter, body []byte) {
	var payload GitHubAppPushPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	// Get delivery ID for idempotency
	deliveryID := r.Header.Get("X-GitHub-Delivery")
	if deliveryID == "" {
		h.writeError(w, http.StatusBadRequest, "missing delivery ID")
		return
	}

	// Check idempotency
	processed, err := h.idempotencyStore.CheckDeliveryProcessed(r.Context(), deliveryID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to check idempotency")
		return
	}
	if processed {
		h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "duplicate delivery"})
		return
	}

	// Look up app repository by GitHub repo ID
	appRepo, err := h.appRepoStore.GetByGitHubRepoID(r.Context(), payload.Repository.ID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to look up app repository")
		return
	}
	if appRepo == nil {
		h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "repository not tracked"})
		return
	}

	// Look up linked repositories row via the FK
	repo, err := h.repoStore.GetRepositoryByAppRepoID(r.Context(), appRepo.ID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to look up linked repository")
		return
	}
	if repo == nil {
		h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "no linked repository"})
		return
	}

	// Extract commit SHAs
	commitSHAs := make([]string, len(payload.Commits))
	for i, commit := range payload.Commits {
		commitSHAs[i] = commit.ID
	}

	// Create draft
	draft, err := h.draftStore.CreateDraftFromPush(
		r.Context(),
		repo.UserID,
		repo.ID,
		payload.Ref,
		payload.Before,
		payload.After,
		commitSHAs,
	)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to create draft")
		return
	}

	// Mark delivery as processed
	_ = h.idempotencyStore.MarkDeliveryProcessed(r.Context(), deliveryID, repo.ID)

	// Log activity if configured
	if h.activityStore != nil {
		draftID := draft.ID
		_, _ = h.activityStore.CreateActivity(
			r.Context(),
			repo.UserID,
			"draft_created",
			&draftID,
			fmt.Sprintf("Draft created from push to %s (%s)", payload.Ref, payload.Repository.FullName),
		)
	}

	// Trigger AI generation if configured
	if h.aiGenerator != nil {
		if err := h.aiGenerator.TriggerGeneration(r.Context(), draft.ID); err != nil {
			log.Printf("AI generation failed for draft %s: %v", draft.ID, err)
		}
	}

	h.writeJSON(w, http.StatusOK, GitHubAppWebhookResponse{Status: "ok", Message: "draft created", DraftID: draft.ID})
}

// =============================================================================
// Helpers
// =============================================================================

func (h *GitHubAppWebhookHandler) validateSignature(payload []byte, signature, secret string) bool {
	signature = strings.TrimPrefix(signature, "sha256=")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

func (h *GitHubAppWebhookHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *GitHubAppWebhookHandler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, ErrorResponse{Error: message})
}
