// Package handlers provides HTTP request handlers for the Lambda function.
// This includes GitHub webhook validation and payload processing.
package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mikelady/roxas/internal/models"
)

// WebhookHandler handles GitHub webhook requests
type WebhookHandler struct {
	secret string
}

// NewWebhookHandler creates a new webhook handler with the given secret
func NewWebhookHandler(secret string) *WebhookHandler {
	return &WebhookHandler{
		secret: secret,
	}
}

// ServeHTTP implements http.Handler
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// Validate signature
	signature := r.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		http.Error(w, "Missing signature", http.StatusUnauthorized)
		return
	}

	if !h.validateSignature(body, signature) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// Parse commit data
	commit, err := extractCommitFromWebhook(body)
	if err != nil {
		http.Error(w, "Failed to parse webhook payload", http.StatusBadRequest)
		return
	}

	// TODO: In TB11, we'll process the commit here
	// For now, just acknowledge receipt
	_ = commit

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Webhook received"))
}

// validateSignature verifies the HMAC signature from GitHub
func (h *WebhookHandler) validateSignature(payload []byte, signature string) bool {
	// Remove "sha256=" prefix
	signature = strings.TrimPrefix(signature, "sha256=")

	// Compute expected signature
	mac := hmac.New(sha256.New, []byte(h.secret))
	mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	// Compare
	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

// ValidateSignatureForTest exposes signature validation for property testing.
// This method allows tests to verify that webhook secrets can correctly validate
// HMAC-SHA256 signatures as used by GitHub webhooks.
func (h *WebhookHandler) ValidateSignatureForTest(payload []byte, signature string) bool {
	return h.validateSignature(payload, signature)
}

// GitHubWebhookPayload represents the GitHub webhook JSON structure
type GitHubWebhookPayload struct {
	Repository struct {
		HTMLURL string `json:"html_url"`
	} `json:"repository"`
	Commits []struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		Author  struct {
			Name string `json:"name"`
		} `json:"author"`
	} `json:"commits"`
}

// extractCommitFromWebhook parses GitHub webhook payload and extracts commit info
func extractCommitFromWebhook(payload []byte) (*models.Commit, error) {
	var webhook GitHubWebhookPayload

	err := json.Unmarshal(payload, &webhook)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	if len(webhook.Commits) == 0 {
		return nil, fmt.Errorf("no commits in webhook payload")
	}

	// Get the first commit (most recent)
	firstCommit := webhook.Commits[0]

	commit := &models.Commit{
		Message: firstCommit.Message,
		Author:  firstCommit.Author.Name,
		RepoURL: webhook.Repository.HTMLURL,
		Diff:    "", // TODO: In a future task, we'll fetch the diff from GitHub API
	}

	return commit, nil
}
