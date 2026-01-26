package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mikelady/roxas/internal/auth"
	"github.com/mikelady/roxas/internal/clients"
	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// alice-68: Post Draft Handler Implementation
// POST /drafts/{id}/post?platform=<platform>
// =============================================================================

// Draft represents a draft post (minimal type for handler use)
type Draft struct {
	ID               string
	UserID           string
	RepositoryID     string
	Status           string
	GeneratedContent *string
	EditedContent    *string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Supported platforms for posting
var supportedPostPlatforms = map[string]bool{
	services.PlatformThreads: true,
	// Future: services.PlatformBluesky, etc.
}

// DraftStoreForPost defines the interface for draft persistence (post-specific)
type DraftStoreForPost interface {
	GetDraft(ctx context.Context, draftID string) (*Draft, error)
	GetDraftByUserID(ctx context.Context, draftID, userID string) (*Draft, error)
	UpdateDraftStatus(ctx context.Context, draftID, status string) error
}

// PostStoreForDraft defines the interface for creating posts from drafts
type PostStoreForDraft interface {
	CreatePostFromDraft(ctx context.Context, draftID, userID, platform, content string) (*PostFromDraft, error)
	UpdatePostResult(ctx context.Context, postID string, platformPostID, platformPostURL string, postedAt time.Time) error
	UpdatePostError(ctx context.Context, postID, errorMessage string) error
	GetPostByID(ctx context.Context, postID string) (*PostFromDraft, error)
}

// CredentialStoreForDraft defines credential lookup for drafts
type CredentialStoreForDraft interface {
	GetCredentials(ctx context.Context, userID, platform string) (*services.PlatformCredentials, error)
}

// PostFromDraft represents a post created from a draft
type PostFromDraft struct {
	ID              string
	DraftID         string
	UserID          string
	Platform        string
	Content         string
	Status          string
	PlatformPostID  string
	PlatformPostURL string
	ErrorMessage    string
	CreatedAt       time.Time
	PostedAt        *time.Time
}

// PostDraftResponse is the response for posting a draft
type PostDraftResponse struct {
	Post PostFromDraftResponse `json:"post"`
}

// PostFromDraftResponse is the post object in API responses
type PostFromDraftResponse struct {
	ID              string  `json:"id"`
	DraftID         string  `json:"draft_id"`
	Platform        string  `json:"platform"`
	Content         string  `json:"content"`
	Status          string  `json:"status"`
	PlatformPostID  string  `json:"platform_post_id"`
	PlatformPostURL string  `json:"platform_post_url"`
	ErrorMessage    string  `json:"error_message,omitempty"`
	PostedAt        *string `json:"posted_at,omitempty"`
}

// PostDraftHandler handles posting drafts to social platforms
type PostDraftHandler struct {
	draftStore   DraftStoreForPost
	postStore    PostStoreForDraft
	socialClient services.SocialClient
	credStore    CredentialStoreForDraft
}

// NewPostDraftHandler creates a new handler for posting drafts
func NewPostDraftHandler(
	draftStore DraftStoreForPost,
	postStore PostStoreForDraft,
	socialClient services.SocialClient,
	credStore CredentialStoreForDraft,
) *PostDraftHandler {
	return &PostDraftHandler{
		draftStore:   draftStore,
		postStore:    postStore,
		socialClient: socialClient,
		credStore:    credStore,
	}
}

// PostDraft handles POST /drafts/{id}/post?platform=<platform>
// Posts a draft to the specified social platform
func (h *PostDraftHandler) PostDraft(w http.ResponseWriter, r *http.Request) {
	// Get user ID from JWT context
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Extract draft ID from URL path
	// Expected: /drafts/{draftID}/post
	draftID := extractDraftIDFromPath(r.URL.Path)
	if draftID == "" {
		h.writeError(w, http.StatusBadRequest, "missing draft ID")
		return
	}

	// Get platform from query parameter
	platform := r.URL.Query().Get("platform")
	if platform == "" {
		h.writeError(w, http.StatusBadRequest, "platform query parameter is required")
		return
	}

	// Validate platform
	if !supportedPostPlatforms[platform] {
		h.writeError(w, http.StatusBadRequest, "unsupported platform: "+platform)
		return
	}

	// Look up draft with user ownership check
	draft, err := h.draftStore.GetDraftByUserID(r.Context(), draftID, userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to look up draft")
		return
	}
	if draft == nil {
		// Could be not found OR belongs to another user
		// Try to get draft without user filter to distinguish
		draftCheck, _ := h.draftStore.GetDraft(r.Context(), draftID)
		if draftCheck == nil {
			h.writeError(w, http.StatusNotFound, "draft not found")
		} else {
			h.writeError(w, http.StatusForbidden, "access denied")
		}
		return
	}

	// Check if draft is already posted
	if draft.Status == "posted" {
		h.writeError(w, http.StatusBadRequest, "draft has already been posted")
		return
	}

	// Get user's credentials for the platform
	creds, err := h.credStore.GetCredentials(r.Context(), userID, platform)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to look up credentials")
		return
	}
	if creds == nil {
		h.writeError(w, http.StatusBadRequest, "no "+platform+" connection found. Please connect your account first.")
		return
	}

	// Check if token is expired
	if creds.TokenExpiresAt != nil && creds.TokenExpiresAt.Before(time.Now()) {
		h.writeError(w, http.StatusBadRequest, platform+" token has expired. Please reconnect your account.")
		return
	}

	// Get content to post (prefer edited content, fall back to generated)
	var content string
	if draft.EditedContent != nil && *draft.EditedContent != "" {
		content = *draft.EditedContent
	} else if draft.GeneratedContent != nil && *draft.GeneratedContent != "" {
		content = *draft.GeneratedContent
	}
	if content == "" {
		h.writeError(w, http.StatusBadRequest, "draft has no content to post")
		return
	}

	// Validate content before posting
	postContent := services.PostContent{
		Text: content,
	}
	if err := h.socialClient.ValidateContent(postContent); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Create post record before calling API (pending state)
	post, err := h.postStore.CreatePostFromDraft(r.Context(), draftID, userID, platform, content)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to create post record")
		return
	}

	// Call social client to post
	result, err := h.socialClient.Post(r.Context(), postContent)
	if err != nil {
		// Handle specific error types
		if errors.Is(err, clients.ErrThreadsRateLimited) {
			// Rate limited - don't update draft status (can retry later)
			_ = h.postStore.UpdatePostError(r.Context(), post.ID, "rate limited")
			h.writeError(w, http.StatusTooManyRequests, "rate limited by "+platform+". Please try again later.")
			return
		}
		if errors.Is(err, clients.ErrThreadsAuthentication) {
			// Auth error - mark draft as failed
			_ = h.draftStore.UpdateDraftStatus(r.Context(), draftID, "failed")
			_ = h.postStore.UpdatePostError(r.Context(), post.ID, "authentication failed")
			h.writeError(w, http.StatusUnauthorized, platform+" authentication failed. Please reconnect your account.")
			return
		}
		// Generic API error
		_ = h.draftStore.UpdateDraftStatus(r.Context(), draftID, "failed")
		_ = h.postStore.UpdatePostError(r.Context(), post.ID, err.Error())
		h.writeError(w, http.StatusBadGateway, "failed to post to "+platform+": "+err.Error())
		return
	}

	// Success! Update post record with result
	postedAt := time.Now()
	if err := h.postStore.UpdatePostResult(r.Context(), post.ID, result.PostID, result.PostURL, postedAt); err != nil {
		// Post succeeded but we failed to record it - log but don't fail the request
		// The post is live, so report success
	}

	// Update draft status to posted
	if err := h.draftStore.UpdateDraftStatus(r.Context(), draftID, "posted"); err != nil {
		// Draft status update failed, but post succeeded - log but don't fail
	}

	// Build response
	resp := PostDraftResponse{
		Post: PostFromDraftResponse{
			ID:              post.ID,
			DraftID:         draftID,
			Platform:        platform,
			Content:         content,
			Status:          "posted",
			PlatformPostID:  result.PostID,
			PlatformPostURL: result.PostURL,
			PostedAt:        stringPtr(postedAt.Format(time.RFC3339)),
		},
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// extractDraftIDFromPath extracts draft ID from URL path
// Expected format: /drafts/{draftID}/post
func extractDraftIDFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	// drafts/{draftID}/post
	if len(parts) >= 2 && parts[0] == "drafts" {
		return parts[1]
	}
	return ""
}

func (h *PostDraftHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *PostDraftHandler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, ErrorResponse{Error: message})
}

func stringPtr(s string) *string {
	return &s
}
