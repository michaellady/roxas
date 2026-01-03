package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mikelady/roxas/internal/auth"
	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// Posts Handler Implementation (TB19)
// =============================================================================

// Post represents a generated social media post in the database
type Post struct {
	ID        string
	CommitID  string
	Platform  string
	Content   string
	Status    string // draft, posted, failed
	CreatedAt time.Time
}

// Supported platforms for post generation
var supportedPlatforms = map[string]bool{
	services.PlatformLinkedIn:  true,
	services.PlatformTwitter:   true,
	services.PlatformInstagram: true,
	services.PlatformYouTube:   true,
}

// PostStore defines the interface for post persistence
type PostStore interface {
	CreatePost(ctx context.Context, commitID, platform, content string) (*Post, error)
	GetPostByID(ctx context.Context, postID string) (*Post, error)
	GetPostsByUserID(ctx context.Context, userID string) ([]*Post, error)
	UpdatePostStatus(ctx context.Context, postID, status string) error
}

// CommitStoreForPosts defines commit lookup with ownership
type CommitStoreForPosts interface {
	GetCommitByID(ctx context.Context, commitID string) (*services.Commit, error)
	GetCommitOwnerID(ctx context.Context, commitID string) (string, error)
}

// PostGeneratorInterface for generating posts
type PostGeneratorInterface interface {
	Generate(ctx context.Context, platform string, commit *services.Commit) (*services.GeneratedPost, error)
}

// PostsHandler handles posts API endpoints
type PostsHandler struct {
	postStore   PostStore
	commitStore CommitStoreForPosts
	generator   PostGeneratorInterface
}

// NewPostsHandler creates a new posts handler
func NewPostsHandler(postStore PostStore, commitStore CommitStoreForPosts, generator PostGeneratorInterface) *PostsHandler {
	return &PostsHandler{
		postStore:   postStore,
		commitStore: commitStore,
		generator:   generator,
	}
}

// CreatePost handles POST /api/v1/commits/:id/posts?platform=linkedin
func (h *PostsHandler) CreatePost(w http.ResponseWriter, r *http.Request) {
	// Get user ID from JWT context
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Extract commit ID from URL path
	// Expected: /api/v1/commits/{commitID}/posts
	commitID := extractCommitIDFromPath(r.URL.Path)
	if commitID == "" {
		h.writeError(w, http.StatusBadRequest, "missing commit ID")
		return
	}

	// Get platform from query parameter
	platform := r.URL.Query().Get("platform")
	if platform == "" {
		h.writeError(w, http.StatusBadRequest, "platform query parameter is required")
		return
	}

	// Validate platform
	if !supportedPlatforms[platform] {
		h.writeError(w, http.StatusBadRequest, "unsupported platform: "+platform+". Supported: linkedin, twitter, instagram, youtube")
		return
	}

	// Look up commit
	commit, err := h.commitStore.GetCommitByID(r.Context(), commitID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to look up commit")
		return
	}
	if commit == nil {
		h.writeError(w, http.StatusNotFound, "commit not found")
		return
	}

	// Verify ownership - commit must belong to requesting user
	ownerID, err := h.commitStore.GetCommitOwnerID(r.Context(), commitID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to verify ownership")
		return
	}
	if ownerID != userID {
		h.writeError(w, http.StatusForbidden, "access denied")
		return
	}

	// Generate post content
	generated, err := h.generator.Generate(r.Context(), platform, commit)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to generate post: "+err.Error())
		return
	}

	// Store post in database
	post, err := h.postStore.CreatePost(r.Context(), commitID, platform, generated.Content)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to store post")
		return
	}

	// Return created post
	resp := CreatePostResponse{
		Post: PostResponse{
			ID:        post.ID,
			CommitID:  post.CommitID,
			Platform:  post.Platform,
			Content:   post.Content,
			Status:    post.Status,
			CreatedAt: post.CreatedAt.Format(time.RFC3339),
		},
	}

	h.writeJSON(w, http.StatusCreated, resp)
}

// ListPosts handles GET /api/v1/posts
func (h *PostsHandler) ListPosts(w http.ResponseWriter, r *http.Request) {
	// Get user ID from JWT context
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Get user's posts
	posts, err := h.postStore.GetPostsByUserID(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to retrieve posts")
		return
	}

	// Convert to response format
	postResponses := make([]PostResponse, 0, len(posts))
	for _, p := range posts {
		postResponses = append(postResponses, PostResponse{
			ID:        p.ID,
			CommitID:  p.CommitID,
			Platform:  p.Platform,
			Content:   p.Content,
			Status:    p.Status,
			CreatedAt: p.CreatedAt.Format(time.RFC3339),
		})
	}

	resp := ListPostsResponse{
		Posts: postResponses,
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// GetPost handles GET /api/v1/posts/:id
func (h *PostsHandler) GetPost(w http.ResponseWriter, r *http.Request) {
	// Get user ID from JWT context
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Extract post ID from URL path
	// Expected: /api/v1/posts/{postID}
	postID := extractPostIDFromPath(r.URL.Path)
	if postID == "" {
		h.writeError(w, http.StatusBadRequest, "missing post ID")
		return
	}

	// Look up post
	post, err := h.postStore.GetPostByID(r.Context(), postID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to look up post")
		return
	}
	if post == nil {
		h.writeError(w, http.StatusNotFound, "post not found")
		return
	}

	// Verify ownership - post's commit must belong to requesting user
	ownerID, err := h.commitStore.GetCommitOwnerID(r.Context(), post.CommitID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to verify ownership")
		return
	}
	if ownerID != userID {
		h.writeError(w, http.StatusForbidden, "access denied")
		return
	}

	resp := GetPostResponse{
		Post: PostResponse{
			ID:        post.ID,
			CommitID:  post.CommitID,
			Platform:  post.Platform,
			Content:   post.Content,
			Status:    post.Status,
			CreatedAt: post.CreatedAt.Format(time.RFC3339),
		},
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// extractCommitIDFromPath extracts commit ID from URL path
// Expected format: /api/v1/commits/{commitID}/posts
func extractCommitIDFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	// api/v1/commits/{commitID}/posts
	if len(parts) >= 4 && parts[2] == "commits" {
		return parts[3]
	}
	return ""
}

// extractPostIDFromPath extracts post ID from URL path
// Expected format: /api/v1/posts/{postID}
func extractPostIDFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	// api/v1/posts/{postID}
	if len(parts) >= 4 && parts[2] == "posts" {
		return parts[3]
	}
	return ""
}

func (h *PostsHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *PostsHandler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, ErrorResponse{Error: message})
}

// =============================================================================
// Response Types
// =============================================================================

// PostResponse is the post object in API responses
type PostResponse struct {
	ID        string `json:"id"`
	CommitID  string `json:"commit_id"`
	Platform  string `json:"platform"`
	Content   string `json:"content"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// CreatePostResponse is the response for creating a post
type CreatePostResponse struct {
	Post PostResponse `json:"post"`
}

// GetPostResponse is the response for getting a single post
type GetPostResponse struct {
	Post PostResponse `json:"post"`
}

// ListPostsResponse is the response for listing posts
type ListPostsResponse struct {
	Posts []PostResponse `json:"posts"`
}
