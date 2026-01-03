package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// WebhookRepositoryStore defines the interface for repository lookup in webhook handling
type WebhookRepositoryStore interface {
	GetRepositoryByID(ctx context.Context, repoID string) (*Repository, error)
}

// StoredCommit represents a commit stored in the database
type StoredCommit struct {
	ID           string
	RepositoryID string
	CommitSHA    string
	GitHubURL    string
	Message      string
	Author       string
	Timestamp    time.Time
}

// CommitStore defines the interface for commit persistence
type CommitStore interface {
	StoreCommit(ctx context.Context, commit *StoredCommit) error
	GetCommitBySHA(ctx context.Context, repoID, sha string) (*StoredCommit, error)
}

// WebhookDelivery represents a webhook delivery attempt for tracking
type WebhookDelivery struct {
	RepositoryID string
	EventType    string
	Payload      string
	ResponseCode int
	ResponseBody string
	Success      bool
	ErrorMessage string
	DeliveredAt  time.Time
}

// WebhookDeliveryStore defines the interface for recording webhook deliveries
type WebhookDeliveryStore interface {
	RecordDelivery(ctx context.Context, delivery *WebhookDelivery) error
}

// MultiTenantWebhookHandler handles GitHub webhooks for multiple repositories
type MultiTenantWebhookHandler struct {
	repoStore     WebhookRepositoryStore
	commitStore   CommitStore
	deliveryStore WebhookDeliveryStore // optional, for tracking deliveries
}

// NewMultiTenantWebhookHandler creates a new multi-tenant webhook handler
func NewMultiTenantWebhookHandler(repoStore WebhookRepositoryStore, commitStore CommitStore) *MultiTenantWebhookHandler {
	return &MultiTenantWebhookHandler{
		repoStore:   repoStore,
		commitStore: commitStore,
	}
}

// WithDeliveryStore adds a delivery store for tracking webhook deliveries
func (h *MultiTenantWebhookHandler) WithDeliveryStore(store WebhookDeliveryStore) *MultiTenantWebhookHandler {
	h.deliveryStore = store
	return h
}

// WebhookResponse is the JSON response for webhook requests
type WebhookResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Commits int    `json:"commits_processed,omitempty"`
}

// GitHubPushPayload represents the GitHub push webhook JSON structure
type GitHubPushPayload struct {
	Ref        string `json:"ref"`
	Repository struct {
		HTMLURL  string `json:"html_url"`
		FullName string `json:"full_name"`
	} `json:"repository"`
	Commits []GitHubCommit `json:"commits"`
}

// GitHubCommit represents a commit in the GitHub webhook payload
type GitHubCommit struct {
	ID        string `json:"id"`
	Message   string `json:"message"`
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
	Author    struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"author"`
}

// ServeHTTP implements http.Handler
// Route: POST /webhooks/github/:repo_id
func (h *MultiTenantWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract repo_id from URL path
	// Expected format: /webhooks/github/{repo_id}
	repoID := extractRepoIDFromPath(r.URL.Path)
	if repoID == "" {
		h.writeError(w, http.StatusBadRequest, "missing repository ID")
		return
	}

	// Extract event type EARLY - before signature validation
	// This ensures we have the eventType for delivery recording even on auth failures
	eventType := r.Header.Get("X-GitHub-Event")

	// Look up repository by ID (multi-tenant boundary)
	repo, err := h.repoStore.GetRepositoryByID(r.Context(), repoID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to look up repository")
		return
	}
	if repo == nil {
		h.writeError(w, http.StatusNotFound, "repository not found")
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to read request body")
		return
	}
	defer r.Body.Close()

	// Validate GitHub signature using repository's webhook secret
	signature := r.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		// Record auth failure with TRUNCATED payload (security: don't store full attacker-controlled data)
		h.recordDeliveryAuthFailure(r.Context(), repoID, eventType, body, http.StatusUnauthorized, "missing signature")
		h.writeError(w, http.StatusUnauthorized, "missing signature")
		return
	}

	if !h.validateSignature(body, signature, repo.WebhookSecret) {
		// Record auth failure with TRUNCATED payload (security: don't store full attacker-controlled data)
		h.recordDeliveryAuthFailure(r.Context(), repoID, eventType, body, http.StatusUnauthorized, "invalid signature")
		h.writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	// Handle ping event (GitHub health check)
	if eventType == "ping" {
		response := WebhookResponse{Status: "ok", Message: "pong"}
		h.recordDeliverySuccess(r.Context(), repoID, eventType, body, http.StatusOK, response)
		h.writeJSON(w, http.StatusOK, response)
		return
	}

	// Handle push event
	if eventType == "push" {
		commitsProcessed, err := h.handlePushEvent(r, body, repo)
		if err != nil {
			h.recordDelivery(r.Context(), repoID, eventType, string(body), http.StatusBadRequest, err.Error(), false)
			h.writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		response := WebhookResponse{Status: "ok", Message: "commits processed", Commits: commitsProcessed}
		h.recordDeliverySuccess(r.Context(), repoID, eventType, body, http.StatusOK, response)
		h.writeJSON(w, http.StatusOK, response)
		return
	}

	// Unknown event type - acknowledge but ignore
	response := WebhookResponse{Status: "ok", Message: "event ignored"}
	h.recordDeliverySuccess(r.Context(), repoID, eventType, body, http.StatusOK, response)
	h.writeJSON(w, http.StatusOK, response)
}

// extractRepoIDFromPath extracts the repository ID from the URL path
func extractRepoIDFromPath(path string) string {
	// Expected format: /webhooks/github/{repo_id}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "webhooks" && parts[1] == "github" {
		return parts[2]
	}
	return ""
}

// validateSignature verifies the GitHub HMAC-SHA256 signature
func (h *MultiTenantWebhookHandler) validateSignature(payload []byte, signature, secret string) bool {
	// Remove "sha256=" prefix
	signature = strings.TrimPrefix(signature, "sha256=")

	// Compute expected signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison
	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

// handlePushEvent processes a GitHub push event and stores commits
func (h *MultiTenantWebhookHandler) handlePushEvent(r *http.Request, body []byte, repo *Repository) (int, error) {
	var payload GitHubPushPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, err
	}

	// Store each commit
	commitsProcessed := 0
	for _, commit := range payload.Commits {
		// Parse timestamp
		timestamp, _ := time.Parse(time.RFC3339, commit.Timestamp)
		if timestamp.IsZero() {
			timestamp = time.Now()
		}

		storedCommit := &StoredCommit{
			RepositoryID: repo.ID,
			CommitSHA:    commit.ID,
			GitHubURL:    commit.URL,
			Message:      commit.Message,
			Author:       commit.Author.Name,
			Timestamp:    timestamp,
		}

		// Store commit (implementation should handle deduplication)
		if err := h.commitStore.StoreCommit(r.Context(), storedCommit); err != nil {
			// Log error but continue processing other commits
			continue
		}
		commitsProcessed++
	}

	return commitsProcessed, nil
}

func (h *MultiTenantWebhookHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *MultiTenantWebhookHandler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, ErrorResponse{Error: message})
}

// =============================================================================
// Webhook Delivery Recording (with security-conscious payload handling)
// =============================================================================

// maxPayloadBytesForAuthFailure is the maximum payload size stored for auth failures.
// This prevents attackers from using failed webhook requests to store arbitrary data.
const maxPayloadBytesForAuthFailure = 256

// recordDelivery records a webhook delivery attempt (if store is configured)
func (h *MultiTenantWebhookHandler) recordDelivery(ctx context.Context, repoID, eventType, payload string, statusCode int, responseBody string, success bool) {
	if h.deliveryStore == nil {
		return
	}

	delivery := &WebhookDelivery{
		RepositoryID: repoID,
		EventType:    eventType,
		Payload:      payload,
		ResponseCode: statusCode,
		ResponseBody: responseBody,
		Success:      success,
		DeliveredAt:  time.Now(),
	}
	if !success {
		delivery.ErrorMessage = responseBody
	}

	// Best-effort recording - don't fail the request if recording fails
	_ = h.deliveryStore.RecordDelivery(ctx, delivery)
}

// recordDeliverySuccess records a successful webhook delivery with full payload
func (h *MultiTenantWebhookHandler) recordDeliverySuccess(ctx context.Context, repoID, eventType string, payload []byte, statusCode int, response interface{}) {
	if h.deliveryStore == nil {
		return
	}

	responseBody, _ := json.Marshal(response)
	h.recordDelivery(ctx, repoID, eventType, string(payload), statusCode, string(responseBody), true)
}

// recordDeliveryAuthFailure records an authentication failure with TRUNCATED payload.
// Security: We don't store full payloads for auth failures to prevent attackers
// from using forged webhook requests to store arbitrary data in our database.
// Instead, we store the first N bytes plus a hash for debugging.
func (h *MultiTenantWebhookHandler) recordDeliveryAuthFailure(ctx context.Context, repoID, eventType string, payload []byte, statusCode int, errorMessage string) {
	if h.deliveryStore == nil {
		return
	}

	// Truncate payload for security - only store first N bytes + hash
	truncatedPayload := truncatePayloadForAuthFailure(payload)

	delivery := &WebhookDelivery{
		RepositoryID: repoID,
		EventType:    eventType,
		Payload:      truncatedPayload,
		ResponseCode: statusCode,
		ResponseBody: errorMessage,
		Success:      false,
		ErrorMessage: errorMessage,
		DeliveredAt:  time.Now(),
	}

	// Best-effort recording
	_ = h.deliveryStore.RecordDelivery(ctx, delivery)
}

// truncatePayloadForAuthFailure truncates a payload for auth failure recording.
// Returns first N bytes plus a SHA256 hash of the full payload for correlation.
func truncatePayloadForAuthFailure(payload []byte) string {
	if len(payload) <= maxPayloadBytesForAuthFailure {
		return string(payload)
	}

	// Compute hash of full payload for debugging/correlation
	hash := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(hash[:])

	// Return truncated payload with hash
	truncated := payload[:maxPayloadBytesForAuthFailure]
	return fmt.Sprintf("%s...[truncated, %d bytes total, sha256:%s]", string(truncated), len(payload), hashHex[:16])
}
