package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/mikelady/roxas/internal/auth"
)

// MaxDraftContentLength is the maximum length for edited content (Threads limit)
const MaxDraftContentLength = 500

// Draft represents a draft post awaiting user review
type Draft struct {
	ID               string     `json:"id"`
	UserID           string     `json:"user_id"`
	RepositoryID     string     `json:"repository_id"`
	Ref              string     `json:"ref"`
	BeforeSHA        *string    `json:"before_sha"`
	AfterSHA         string     `json:"after_sha"`
	CommitSHAs       []string   `json:"commit_shas"`
	CommitCount      int        `json:"commit_count"`
	GeneratedContent *string    `json:"generated_content"`
	EditedContent    *string    `json:"edited_content"`
	Status           string     `json:"status"` // draft, posted, partial, failed, error
	ErrorMessage     *string    `json:"error_message"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	PostedAt         *time.Time `json:"posted_at"`
}

// DraftStore defines the interface for draft persistence
type DraftStore interface {
	GetDraftByID(ctx context.Context, draftID string) (*Draft, error)
	GetDraftsByUserID(ctx context.Context, userID string, limit, offset int) ([]*Draft, error)
	UpdateDraftContent(ctx context.Context, draftID, editedContent string) error
	UpdateDraftStatus(ctx context.Context, draftID, status string, errorMsg *string) error
	DeleteDraft(ctx context.Context, draftID string) error
}

// AIGenerator defines the interface for AI content generation
type AIGenerator interface {
	GeneratePostContent(ctx context.Context, commitInfo interface{}) (string, error)
}

// DraftHandler handles draft-related HTTP requests
type DraftHandler struct {
	store DraftStore
	aiGen AIGenerator
}

// NewDraftHandler creates a new draft handler
func NewDraftHandler(store DraftStore, aiGen interface{}) *DraftHandler {
	var generator AIGenerator
	if aiGen != nil {
		if g, ok := aiGen.(AIGenerator); ok {
			generator = g
		}
	}
	return &DraftHandler{
		store: store,
		aiGen: generator,
	}
}

// HandleEdit handles POST /drafts/{id}/edit
// Updates the edited_content field of a draft
func (h *DraftHandler) HandleEdit(w http.ResponseWriter, r *http.Request, draftID string) {
	// Get user ID from context
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	content := r.FormValue("content")

	// Validate content length
	if len(content) > MaxDraftContentLength {
		http.Error(w, "Content exceeds maximum length", http.StatusBadRequest)
		return
	}

	// Get draft to verify ownership
	draft, err := h.store.GetDraftByID(r.Context(), draftID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if draft == nil {
		http.Error(w, "Draft not found", http.StatusNotFound)
		return
	}

	// Verify ownership
	if draft.UserID != userID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Update the content
	if err := h.store.UpdateDraftContent(r.Context(), draftID, content); err != nil {
		http.Error(w, "Failed to update draft", http.StatusInternalServerError)
		return
	}

	// Return success
	w.WriteHeader(http.StatusOK)
}

// HandleDelete handles POST /drafts/{id}/delete
// Deletes a draft (only if not already posted)
func (h *DraftHandler) HandleDelete(w http.ResponseWriter, r *http.Request, draftID string) {
	// Get user ID from context
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get draft to verify ownership and status
	draft, err := h.store.GetDraftByID(r.Context(), draftID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if draft == nil {
		http.Error(w, "Draft not found", http.StatusNotFound)
		return
	}

	// Verify ownership
	if draft.UserID != userID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Cannot delete already posted drafts
	if draft.Status == "posted" {
		http.Error(w, "Cannot delete posted draft", http.StatusBadRequest)
		return
	}

	// Delete the draft
	if err := h.store.DeleteDraft(r.Context(), draftID); err != nil {
		http.Error(w, "Failed to delete draft", http.StatusInternalServerError)
		return
	}

	// Redirect to drafts list
	http.Redirect(w, r, "/drafts", http.StatusSeeOther)
}

// HandleRegenerate handles POST /drafts/{id}/regenerate
// Regenerates AI content for a draft
func (h *DraftHandler) HandleRegenerate(w http.ResponseWriter, r *http.Request, draftID string) {
	// Get user ID from context
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get draft to verify ownership and status
	draft, err := h.store.GetDraftByID(r.Context(), draftID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if draft == nil {
		http.Error(w, "Draft not found", http.StatusNotFound)
		return
	}

	// Verify ownership
	if draft.UserID != userID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Cannot regenerate already posted drafts
	if draft.Status == "posted" {
		http.Error(w, "Cannot regenerate posted draft", http.StatusBadRequest)
		return
	}

	// Check if AI generator is available
	if h.aiGen == nil {
		http.Error(w, "AI generation not available", http.StatusServiceUnavailable)
		return
	}

	// Regenerate content
	// Pass draft info to AI generator (it will fetch commit details)
	_, err = h.aiGen.GeneratePostContent(r.Context(), draft)
	if err != nil {
		http.Error(w, "Failed to regenerate content", http.StatusInternalServerError)
		return
	}

	// Note: The AI generator should update the draft's generated_content
	// and clear edited_content. For now, we just return success.
	// A more complete implementation would update the store here.

	// Return success
	w.WriteHeader(http.StatusOK)
}
