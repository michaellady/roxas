package handlers

import (
	"net/http"
)

// MultiTenantWebhookHandler handles GitHub webhooks for multiple repositories
type MultiTenantWebhookHandler struct {
	repoStore   WebhookRepositoryStore
	commitStore CommitStore
}

// NewMultiTenantWebhookHandler creates a new multi-tenant webhook handler
func NewMultiTenantWebhookHandler(repoStore WebhookRepositoryStore, commitStore CommitStore) *MultiTenantWebhookHandler {
	return &MultiTenantWebhookHandler{
		repoStore:   repoStore,
		commitStore: commitStore,
	}
}

// ServeHTTP implements http.Handler
// Route: POST /webhooks/github/:repo_id
// TODO: Implement in TB13 to make tests pass
func (h *MultiTenantWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Stub: returns 501 Not Implemented
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error": "not implemented"}`))
}
