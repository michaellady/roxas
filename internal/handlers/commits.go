package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/mikelady/roxas/internal/auth"
	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// Commits Handler Implementation (TB-WEB-06)
// =============================================================================

// CommitLister defines the interface for listing user commits
type CommitLister interface {
	ListCommitsByUser(ctx context.Context, userID string) ([]*services.Commit, error)
}

// CommitsHandler handles commits API endpoints
type CommitsHandler struct {
	commitLister CommitLister
}

// NewCommitsHandler creates a new commits handler
func NewCommitsHandler(commitLister CommitLister) *CommitsHandler {
	return &CommitsHandler{
		commitLister: commitLister,
	}
}

// ListCommits handles GET /api/v1/commits
func (h *CommitsHandler) ListCommits(w http.ResponseWriter, r *http.Request) {
	// Get user ID from JWT context
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Get user's commits
	commits, err := h.commitLister.ListCommitsByUser(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to retrieve commits")
		return
	}

	// Convert to response format
	commitResponses := make([]CommitResponse, 0, len(commits))
	for _, c := range commits {
		commitResponses = append(commitResponses, CommitResponse{
			ID:        c.ID,
			SHA:       c.CommitSHA,
			Message:   c.Message,
			Author:    c.Author,
			Timestamp: c.Timestamp.Format(time.RFC3339),
			GitHubURL: c.GitHubURL,
		})
	}

	resp := ListCommitsResponse{
		Commits: commitResponses,
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func (h *CommitsHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *CommitsHandler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, ErrorResponse{Error: message})
}

// =============================================================================
// Response Types
// =============================================================================

// CommitResponse is the commit object in API responses
type CommitResponse struct {
	ID        string `json:"id"`
	SHA       string `json:"sha"`
	Message   string `json:"message"`
	Author    string `json:"author"`
	Timestamp string `json:"timestamp"`
	GitHubURL string `json:"github_url"`
}

// ListCommitsResponse is the response for listing commits
type ListCommitsResponse struct {
	Commits []CommitResponse `json:"commits"`
}
