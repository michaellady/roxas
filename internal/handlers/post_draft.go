package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// alice-91: Post Draft Handler (TDD - RED phase stub)
// This is a stub implementation to allow tests to compile.
// Implementation pending in alice-68.
// =============================================================================

// DraftStore defines the interface for draft persistence
type DraftStore interface {
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

// SocialClientProvider provides SocialClient instances for platforms
type SocialClientProvider interface {
	GetClient(ctx context.Context, userID, platform string) (services.SocialClient, error)
}

// CredentialStoreForDraft defines credential lookup for drafts
type CredentialStoreForDraft interface {
	GetCredentials(ctx context.Context, userID, platform string) (*services.PlatformCredentials, error)
}

// PostDraftHandler handles posting drafts to social platforms
type PostDraftHandler struct {
	draftStore  DraftStore
	postStore   PostStoreForDraft
	socialClient services.SocialClient
	credStore   CredentialStoreForDraft
}

// NewPostDraftHandler creates a new handler for posting drafts
// TODO(alice-68): Implement full handler logic
func NewPostDraftHandler(
	draftStore DraftStore,
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
// TODO(alice-68): Implement full handler logic
func (h *PostDraftHandler) PostDraft(w http.ResponseWriter, r *http.Request) {
	// Stub: Not implemented yet
	// This will cause tests to fail (after they stop skipping)
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
