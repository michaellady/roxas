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

// =============================================================================
// Draft-Creating Webhook Handler (alice-64)
// =============================================================================

// DraftWebhookStore defines the interface for draft persistence from webhooks
type DraftWebhookStore interface {
	CreateDraftFromPush(ctx context.Context, userID, repoID, ref, beforeSHA, afterSHA string, commitSHAs []string) (*WebhookDraft, error)
	GetDraftByPushSignature(ctx context.Context, repoID, beforeSHA, afterSHA string) (*WebhookDraft, error)
}

// WebhookDraft represents a draft created from a webhook push event
type WebhookDraft struct {
	ID               string
	UserID           string
	RepositoryID     string
	Ref              string
	BeforeSHA        string
	AfterSHA         string
	CommitSHAs       []string
	GeneratedContent string
	EditedContent    string
	Status           string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// ActivityStore defines the interface for activity logging
type ActivityStore interface {
	CreateActivity(ctx context.Context, userID, activityType string, draftID *string, message string) (*WebhookActivity, error)
}

// WebhookActivity represents an activity log entry
type WebhookActivity struct {
	ID        string
	UserID    string
	Type      string
	DraftID   *string
	PostID    *string
	Platform  string
	Message   string
	CreatedAt time.Time
}

// AIGeneratorService defines the interface for async AI content generation
type AIGeneratorService interface {
	TriggerGeneration(ctx context.Context, draftID string) error
}

// IdempotencyStore defines the interface for delivery idempotency checks
type IdempotencyStore interface {
	CheckDeliveryProcessed(ctx context.Context, deliveryID string) (bool, error)
	MarkDeliveryProcessed(ctx context.Context, deliveryID, repoID string) error
}

// DraftCreatingWebhookHandler handles GitHub webhooks and creates drafts
type DraftCreatingWebhookHandler struct {
	repoStore        WebhookRepositoryStore
	draftStore       DraftWebhookStore
	idempotencyStore IdempotencyStore
	activityStore    ActivityStore      // optional
	aiGenerator      AIGeneratorService // optional
	deliveryStore    WebhookDeliveryStore // optional, for tracking deliveries
}

// NewDraftCreatingWebhookHandler creates a new draft-creating webhook handler
func NewDraftCreatingWebhookHandler(repoStore WebhookRepositoryStore, draftStore DraftWebhookStore, idempotencyStore IdempotencyStore) *DraftCreatingWebhookHandler {
	return &DraftCreatingWebhookHandler{
		repoStore:        repoStore,
		draftStore:       draftStore,
		idempotencyStore: idempotencyStore,
	}
}

// WithActivityStore adds an activity store for logging
func (h *DraftCreatingWebhookHandler) WithActivityStore(store ActivityStore) *DraftCreatingWebhookHandler {
	h.activityStore = store
	return h
}

// WithAIGenerator adds an AI generator service
func (h *DraftCreatingWebhookHandler) WithAIGenerator(gen AIGeneratorService) *DraftCreatingWebhookHandler {
	h.aiGenerator = gen
	return h
}

// WithDeliveryStore adds a delivery store for tracking webhook deliveries
func (h *DraftCreatingWebhookHandler) WithDeliveryStore(store WebhookDeliveryStore) *DraftCreatingWebhookHandler {
	h.deliveryStore = store
	return h
}

// DraftWebhookResponse is the JSON response for draft webhook requests
type DraftWebhookResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	DraftID string `json:"draft_id,omitempty"`
}

// GitHubPushPayloadWithSHAs extends GitHubPushPayload with before/after SHAs
type GitHubPushPayloadWithSHAs struct {
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
	Repository struct {
		HTMLURL  string `json:"html_url"`
		FullName string `json:"full_name"`
	} `json:"repository"`
	Commits []GitHubCommit `json:"commits"`
}

// ServeHTTP implements http.Handler for DraftCreatingWebhookHandler
func (h *DraftCreatingWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract repo_id from URL path
	repoID := extractRepoIDFromPath(r.URL.Path)
	if repoID == "" {
		h.writeError(w, http.StatusBadRequest, "missing repository ID")
		return
	}

	// Extract event type
	eventType := r.Header.Get("X-GitHub-Event")

	// Extract delivery ID for idempotency
	deliveryID := r.Header.Get("X-GitHub-Delivery")

	// Look up repository by ID
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

	// Validate GitHub signature
	signature := r.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		h.writeError(w, http.StatusUnauthorized, "missing signature")
		return
	}

	if !h.validateSignature(body, signature, repo.WebhookSecret) {
		h.writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	// Handle ping event
	if eventType == "ping" {
		response := DraftWebhookResponse{Status: "ok", Message: "pong"}
		h.writeJSON(w, http.StatusOK, response)
		return
	}

	// Handle push event
	if eventType == "push" {
		// Require delivery_id for push events (idempotency)
		if deliveryID == "" {
			h.writeError(w, http.StatusBadRequest, "missing delivery ID")
			return
		}

		// Check delivery_id idempotency
		processed, err := h.idempotencyStore.CheckDeliveryProcessed(r.Context(), deliveryID)
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to check idempotency")
			return
		}
		if processed {
			response := DraftWebhookResponse{Status: "ok", Message: "duplicate delivery"}
			h.writeJSON(w, http.StatusOK, response)
			return
		}

		// Parse push payload
		var payload GitHubPushPayloadWithSHAs
		if err := json.Unmarshal(body, &payload); err != nil {
			h.writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Dual idempotency: check push signature (repo_id + before_sha + after_sha)
		existingDraft, err := h.draftStore.GetDraftByPushSignature(r.Context(), repoID, payload.Before, payload.After)
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to check push signature")
			return
		}
		if existingDraft != nil {
			// Already processed this exact push - return success (idempotent)
			// Mark this delivery_id as processed too
			_ = h.idempotencyStore.MarkDeliveryProcessed(r.Context(), deliveryID, repoID)
			response := DraftWebhookResponse{Status: "ok", Message: "duplicate delivery", DraftID: existingDraft.ID}
			h.writeJSON(w, http.StatusOK, response)
			return
		}

		// Extract commit SHAs from payload
		commitSHAs := make([]string, len(payload.Commits))
		for i, commit := range payload.Commits {
			commitSHAs[i] = commit.ID
		}

		// Create draft
		draft, err := h.draftStore.CreateDraftFromPush(
			r.Context(),
			repo.UserID,
			repoID,
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
		_ = h.idempotencyStore.MarkDeliveryProcessed(r.Context(), deliveryID, repoID)

		// Create activity record (if activity store configured)
		if h.activityStore != nil {
			draftID := draft.ID
			_, _ = h.activityStore.CreateActivity(
				r.Context(),
				repo.UserID,
				"draft_created",
				&draftID,
				fmt.Sprintf("Draft created from push to %s", payload.Ref),
			)
		}

		// Trigger async AI generation (if AI generator configured)
		if h.aiGenerator != nil {
			// Fire and forget - don't block on AI generation
			go func() {
				ctx := context.Background()
				_ = h.aiGenerator.TriggerGeneration(ctx, draft.ID)
			}()
		}

		response := DraftWebhookResponse{Status: "ok", Message: "draft created", DraftID: draft.ID}
		h.writeJSON(w, http.StatusOK, response)
		return
	}

	// Unknown event type - acknowledge but ignore
	response := DraftWebhookResponse{Status: "ok", Message: "event ignored"}
	h.writeJSON(w, http.StatusOK, response)
}

// validateSignature verifies the GitHub HMAC-SHA256 signature
func (h *DraftCreatingWebhookHandler) validateSignature(payload []byte, signature, secret string) bool {
	// Remove "sha256=" prefix
	signature = strings.TrimPrefix(signature, "sha256=")

	// Compute expected signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison
	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

func (h *DraftCreatingWebhookHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *DraftCreatingWebhookHandler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, ErrorResponse{Error: message})
}
