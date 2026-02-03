package handlers

import (
	"context"
	"errors"
	"testing"
	"time"
)

// =============================================================================
// Unit Tests: Repository Removal (Webhook Cleanup, Draft Preservation)
//
// These tests verify the behavior of repository removal as specified in SPEC.md:
//
// Remove Repo Flow:
// - User clicks "Remove" on repo card
// - Confirmation modal: "Remove [repo-name]? This will stop tracking pushes."
// - On confirm:
//   - Try to delete webhook from GitHub via API
//   - If GitHub token expired: Show warning "Webhook may still exist on GitHub.
//     You can remove it manually in repo settings."
//   - Remove repo from database regardless
// - Existing drafts from this repo are kept (orphaned but viewable)
//
// Run with: go test -v ./internal/handlers -run TestRepositoryRemoval
// =============================================================================

// MockGitHubWebhookDeleter simulates GitHub webhook deletion
type MockGitHubWebhookDeleter struct {
	DeletedWebhooks []WebhookDeleteRequest
	ShouldError     bool
	ErrorType       string // "auth_expired", "not_found", "rate_limited", "generic"
}

type WebhookDeleteRequest struct {
	Owner     string
	Repo      string
	WebhookID int64
}

func NewMockGitHubWebhookDeleter() *MockGitHubWebhookDeleter {
	return &MockGitHubWebhookDeleter{
		DeletedWebhooks: make([]WebhookDeleteRequest, 0),
	}
}

func (m *MockGitHubWebhookDeleter) DeleteWebhook(ctx context.Context, owner, repo string, webhookID int64) error {
	if m.ShouldError {
		switch m.ErrorType {
		case "auth_expired":
			return ErrGitHubAuthExpired
		case "not_found":
			return ErrGitHubWebhookNotFound
		case "rate_limited":
			return ErrGitHubRateLimited
		default:
			return errors.New("generic error")
		}
	}
	m.DeletedWebhooks = append(m.DeletedWebhooks, WebhookDeleteRequest{
		Owner:     owner,
		Repo:      repo,
		WebhookID: webhookID,
	})
	return nil
}

func (m *MockGitHubWebhookDeleter) SetError(errorType string) {
	m.ShouldError = true
	m.ErrorType = errorType
}

// MockDraftPreserver simulates draft store operations for removal
type MockDraftPreserver struct {
	Drafts         map[string]*RemovalDraft
	OrphanedDrafts []string // draft IDs that had their repository_id cleared
}

// RemovalDraft is a test-specific draft type that supports nullable RepositoryID
// for testing draft preservation during repository removal.
// Note: The actual Draft type in post_draft.go uses non-nullable RepositoryID.
// This test type documents the expected behavior per SPEC.md:
// "Existing drafts from this repo are kept (orphaned but viewable)"
type RemovalDraft struct {
	ID           string
	UserID       string
	RepositoryID *string // nullable for orphaned drafts (as per SPEC requirement)
	Content      string
	Status       string
	CreatedAt    time.Time
}

func NewMockDraftPreserver() *MockDraftPreserver {
	return &MockDraftPreserver{
		Drafts:         make(map[string]*RemovalDraft),
		OrphanedDrafts: make([]string, 0),
	}
}

func (m *MockDraftPreserver) AddDraft(draft *RemovalDraft) {
	m.Drafts[draft.ID] = draft
}

func (m *MockDraftPreserver) OrphanDraftsByRepository(ctx context.Context, repositoryID string) error {
	for id, draft := range m.Drafts {
		if draft.RepositoryID != nil && *draft.RepositoryID == repositoryID {
			draft.RepositoryID = nil // Clear the repository reference
			m.OrphanedDrafts = append(m.OrphanedDrafts, id)
		}
	}
	return nil
}

func (m *MockDraftPreserver) GetDraftsByRepository(ctx context.Context, repositoryID string) ([]*RemovalDraft, error) {
	var drafts []*RemovalDraft
	for _, draft := range m.Drafts {
		if draft.RepositoryID != nil && *draft.RepositoryID == repositoryID {
			drafts = append(drafts, draft)
		}
	}
	return drafts, nil
}

func (m *MockDraftPreserver) GetOrphanedDrafts(ctx context.Context, userID string) ([]*RemovalDraft, error) {
	var drafts []*RemovalDraft
	for _, draft := range m.Drafts {
		if draft.UserID == userID && draft.RepositoryID == nil {
			drafts = append(drafts, draft)
		}
	}
	return drafts, nil
}

// MockRepositoryRemovalStore simulates repository store for removal tests
type MockRepositoryRemovalStore struct {
	repos   map[string]*Repository
	deleted []string
}

func NewMockRepositoryRemovalStore() *MockRepositoryRemovalStore {
	return &MockRepositoryRemovalStore{
		repos:   make(map[string]*Repository),
		deleted: make([]string, 0),
	}
}

func (m *MockRepositoryRemovalStore) AddRepository(repo *Repository) {
	m.repos[repo.ID] = repo
}

func (m *MockRepositoryRemovalStore) GetRepositoryByID(ctx context.Context, repoID string) (*Repository, error) {
	if repo, ok := m.repos[repoID]; ok {
		return repo, nil
	}
	return nil, nil
}

func (m *MockRepositoryRemovalStore) DeleteRepository(ctx context.Context, repoID string) error {
	if _, ok := m.repos[repoID]; ok {
		delete(m.repos, repoID)
		m.deleted = append(m.deleted, repoID)
		return nil
	}
	return errors.New("repository not found")
}

func (m *MockRepositoryRemovalStore) WasDeleted(repoID string) bool {
	for _, id := range m.deleted {
		if id == repoID {
			return true
		}
	}
	return false
}

// =============================================================================
// Error Definitions (should be moved to a shared errors package)
// =============================================================================

var (
	ErrGitHubAuthExpired      = errors.New("GitHub authentication expired")
	ErrGitHubWebhookNotFound  = errors.New("webhook not found on GitHub")
	ErrGitHubRateLimited      = errors.New("GitHub API rate limited")
)

// =============================================================================
// RepositoryRemovalResult represents the outcome of a removal operation
// =============================================================================

type RepositoryRemovalResult struct {
	Success        bool
	RepoDeleted    bool
	WebhookDeleted bool
	DraftsOrphaned int
	Warning        string
}

// =============================================================================
// Test: Webhook Cleanup on Repository Removal
// =============================================================================

// TestRepositoryRemoval_WebhookDeletedSuccessfully tests that webhook is deleted
// from GitHub when repository has a valid webhook_id and GitHub token is valid.
func TestRepositoryRemoval_WebhookDeletedSuccessfully(t *testing.T) {
	repoStore := NewMockRepositoryRemovalStore()
	webhookDeleter := NewMockGitHubWebhookDeleter()
	draftStore := NewMockDraftPreserver()

	webhookID := int64(12345)
	repo := &Repository{
		ID:        "repo-123",
		UserID:    "user-456",
		GitHubURL: "https://github.com/testowner/testrepo",
		WebhookID: &webhookID,
		CreatedAt: time.Now(),
	}
	repoStore.AddRepository(repo)

	// Remove repository
	result := removeRepository(context.Background(), repoStore, webhookDeleter, draftStore, repo.ID, "fake-github-token")

	// Verify webhook was deleted with correct parameters
	if len(webhookDeleter.DeletedWebhooks) != 1 {
		t.Errorf("Expected 1 webhook deletion, got %d", len(webhookDeleter.DeletedWebhooks))
	}

	if len(webhookDeleter.DeletedWebhooks) > 0 {
		req := webhookDeleter.DeletedWebhooks[0]
		if req.Owner != "testowner" {
			t.Errorf("Expected owner 'testowner', got '%s'", req.Owner)
		}
		if req.Repo != "testrepo" {
			t.Errorf("Expected repo 'testrepo', got '%s'", req.Repo)
		}
		if req.WebhookID != webhookID {
			t.Errorf("Expected webhookID %d, got %d", webhookID, req.WebhookID)
		}
	}

	// Verify repository was deleted
	if !repoStore.WasDeleted(repo.ID) {
		t.Error("Expected repository to be deleted from store")
	}

	if !result.WebhookDeleted {
		t.Error("Expected WebhookDeleted to be true")
	}
	if !result.RepoDeleted {
		t.Error("Expected RepoDeleted to be true")
	}
	if result.Warning != "" {
		t.Errorf("Expected no warning, got: %s", result.Warning)
	}
}

// TestRepositoryRemoval_WebhookNotDeleted_AuthExpired tests that when GitHub
// token is expired, repository is still deleted but with a warning.
func TestRepositoryRemoval_WebhookNotDeleted_AuthExpired(t *testing.T) {
	repoStore := NewMockRepositoryRemovalStore()
	webhookDeleter := NewMockGitHubWebhookDeleter()
	draftStore := NewMockDraftPreserver()

	webhookDeleter.SetError("auth_expired")

	webhookID := int64(12345)
	repo := &Repository{
		ID:        "repo-123",
		UserID:    "user-456",
		GitHubURL: "https://github.com/testowner/testrepo",
		WebhookID: &webhookID,
		CreatedAt: time.Now(),
	}
	repoStore.AddRepository(repo)

	result := removeRepository(context.Background(), repoStore, webhookDeleter, draftStore, repo.ID, "expired-token")

	// Repository should still be deleted
	if !repoStore.WasDeleted(repo.ID) {
		t.Error("Expected repository to be deleted even when webhook deletion fails")
	}

	// Should have warning about webhook
	if result.Warning == "" {
		t.Error("Expected warning about webhook not being deleted")
	}
	if result.WebhookDeleted {
		t.Error("Expected WebhookDeleted to be false")
	}
	if !result.RepoDeleted {
		t.Error("Expected RepoDeleted to be true")
	}
}

// TestRepositoryRemoval_WebhookNotFound_StillSucceeds tests that if webhook
// doesn't exist on GitHub (already deleted), repository removal still succeeds.
func TestRepositoryRemoval_WebhookNotFound_StillSucceeds(t *testing.T) {
	repoStore := NewMockRepositoryRemovalStore()
	webhookDeleter := NewMockGitHubWebhookDeleter()
	draftStore := NewMockDraftPreserver()

	webhookDeleter.SetError("not_found")

	webhookID := int64(12345)
	repo := &Repository{
		ID:        "repo-123",
		UserID:    "user-456",
		GitHubURL: "https://github.com/testowner/testrepo",
		WebhookID: &webhookID,
		CreatedAt: time.Now(),
	}
	repoStore.AddRepository(repo)

	result := removeRepository(context.Background(), repoStore, webhookDeleter, draftStore, repo.ID, "valid-token")

	// Repository should be deleted
	if !repoStore.WasDeleted(repo.ID) {
		t.Error("Expected repository to be deleted")
	}

	// Webhook not found is not a problem - it's already gone
	if result.Warning != "" {
		t.Errorf("Expected no warning for webhook not found, got: %s", result.Warning)
	}
	if !result.RepoDeleted {
		t.Error("Expected RepoDeleted to be true")
	}
}

// TestRepositoryRemoval_NoWebhookID_SkipsWebhookDeletion tests that if repository
// has no webhook_id stored, webhook deletion is skipped.
func TestRepositoryRemoval_NoWebhookID_SkipsWebhookDeletion(t *testing.T) {
	repoStore := NewMockRepositoryRemovalStore()
	webhookDeleter := NewMockGitHubWebhookDeleter()
	draftStore := NewMockDraftPreserver()

	repo := &Repository{
		ID:        "repo-123",
		UserID:    "user-456",
		GitHubURL: "https://github.com/testowner/testrepo",
		WebhookID: nil, // No webhook ID
		CreatedAt: time.Now(),
	}
	repoStore.AddRepository(repo)

	result := removeRepository(context.Background(), repoStore, webhookDeleter, draftStore, repo.ID, "valid-token")

	// No webhook deletion should be attempted
	if len(webhookDeleter.DeletedWebhooks) != 0 {
		t.Errorf("Expected no webhook deletions, got %d", len(webhookDeleter.DeletedWebhooks))
	}

	// Repository should still be deleted
	if !repoStore.WasDeleted(repo.ID) {
		t.Error("Expected repository to be deleted")
	}
	if !result.RepoDeleted {
		t.Error("Expected RepoDeleted to be true")
	}
}

// TestRepositoryRemoval_RateLimited_StillDeletesRepo tests that rate limiting
// doesn't prevent repository deletion.
func TestRepositoryRemoval_RateLimited_StillDeletesRepo(t *testing.T) {
	repoStore := NewMockRepositoryRemovalStore()
	webhookDeleter := NewMockGitHubWebhookDeleter()
	draftStore := NewMockDraftPreserver()

	webhookDeleter.SetError("rate_limited")

	webhookID := int64(12345)
	repo := &Repository{
		ID:        "repo-123",
		UserID:    "user-456",
		GitHubURL: "https://github.com/testowner/testrepo",
		WebhookID: &webhookID,
		CreatedAt: time.Now(),
	}
	repoStore.AddRepository(repo)

	result := removeRepository(context.Background(), repoStore, webhookDeleter, draftStore, repo.ID, "valid-token")

	// Repository should be deleted regardless
	if !repoStore.WasDeleted(repo.ID) {
		t.Error("Expected repository to be deleted even when rate limited")
	}

	// Should have warning
	if result.Warning == "" {
		t.Error("Expected warning about rate limiting")
	}
	if !result.RepoDeleted {
		t.Error("Expected RepoDeleted to be true")
	}
}

// =============================================================================
// Test: Draft Preservation on Repository Removal
// =============================================================================

// TestRepositoryRemoval_DraftsPreserved tests that drafts are NOT deleted when
// repository is removed - they become orphaned but remain viewable.
func TestRepositoryRemoval_DraftsPreserved(t *testing.T) {
	repoStore := NewMockRepositoryRemovalStore()
	webhookDeleter := NewMockGitHubWebhookDeleter()
	draftStore := NewMockDraftPreserver()

	repoID := "repo-123"
	userID := "user-456"

	repo := &Repository{
		ID:        repoID,
		UserID:    userID,
		GitHubURL: "https://github.com/testowner/testrepo",
		CreatedAt: time.Now(),
	}
	repoStore.AddRepository(repo)

	// Add drafts associated with this repository
	draftStore.AddDraft(&RemovalDraft{
		ID:           "draft-1",
		UserID:       userID,
		RepositoryID: &repoID,
		Content:      "My first draft",
		Status:       "draft",
		CreatedAt:    time.Now(),
	})
	draftStore.AddDraft(&RemovalDraft{
		ID:           "draft-2",
		UserID:       userID,
		RepositoryID: &repoID,
		Content:      "My second draft",
		Status:       "draft",
		CreatedAt:    time.Now(),
	})

	// Remove repository
	result := removeRepository(context.Background(), repoStore, webhookDeleter, draftStore, repoID, "")

	// Repository should be deleted
	if !repoStore.WasDeleted(repoID) {
		t.Error("Expected repository to be deleted")
	}

	// Drafts should still exist but be orphaned
	if len(draftStore.OrphanedDrafts) != 2 {
		t.Errorf("Expected 2 orphaned drafts, got %d", len(draftStore.OrphanedDrafts))
	}

	// Drafts should have nil RepositoryID now
	for _, draft := range draftStore.Drafts {
		if draft.RepositoryID != nil {
			t.Errorf("Expected draft %s to have nil RepositoryID, got %v", draft.ID, draft.RepositoryID)
		}
	}

	if result.DraftsOrphaned != 2 {
		t.Errorf("Expected DraftsOrphaned to be 2, got %d", result.DraftsOrphaned)
	}
}

// TestRepositoryRemoval_OrphanedDraftsStillViewable tests that orphaned drafts
// can still be retrieved and viewed by the user.
func TestRepositoryRemoval_OrphanedDraftsStillViewable(t *testing.T) {
	repoStore := NewMockRepositoryRemovalStore()
	webhookDeleter := NewMockGitHubWebhookDeleter()
	draftStore := NewMockDraftPreserver()

	repoID := "repo-123"
	userID := "user-456"

	repo := &Repository{
		ID:        repoID,
		UserID:    userID,
		GitHubURL: "https://github.com/testowner/testrepo",
		CreatedAt: time.Now(),
	}
	repoStore.AddRepository(repo)

	// Add draft
	draftStore.AddDraft(&RemovalDraft{
		ID:           "draft-1",
		UserID:       userID,
		RepositoryID: &repoID,
		Content:      "Important draft content",
		Status:       "draft",
		CreatedAt:    time.Now(),
	})

	// Remove repository
	removeRepository(context.Background(), repoStore, webhookDeleter, draftStore, repoID, "")

	// User should still be able to retrieve orphaned drafts
	orphanedDrafts, err := draftStore.GetOrphanedDrafts(context.Background(), userID)
	if err != nil {
		t.Fatalf("Failed to get orphaned drafts: %v", err)
	}

	if len(orphanedDrafts) != 1 {
		t.Errorf("Expected 1 orphaned draft, got %d", len(orphanedDrafts))
	}

	if len(orphanedDrafts) > 0 && orphanedDrafts[0].Content != "Important draft content" {
		t.Error("Orphaned draft content should be preserved")
	}
}

// TestRepositoryRemoval_NoDrafts_Succeeds tests that repository removal works
// fine when there are no associated drafts.
func TestRepositoryRemoval_NoDrafts_Succeeds(t *testing.T) {
	repoStore := NewMockRepositoryRemovalStore()
	webhookDeleter := NewMockGitHubWebhookDeleter()
	draftStore := NewMockDraftPreserver()

	repoID := "repo-123"

	repo := &Repository{
		ID:        repoID,
		UserID:    "user-456",
		GitHubURL: "https://github.com/testowner/testrepo",
		CreatedAt: time.Now(),
	}
	repoStore.AddRepository(repo)

	result := removeRepository(context.Background(), repoStore, webhookDeleter, draftStore, repoID, "")

	if !repoStore.WasDeleted(repoID) {
		t.Error("Expected repository to be deleted")
	}

	if result.DraftsOrphaned != 0 {
		t.Errorf("Expected DraftsOrphaned to be 0, got %d", result.DraftsOrphaned)
	}
}

// TestRepositoryRemoval_DraftsFromOtherReposUnaffected tests that drafts from
// other repositories are not affected when one repository is removed.
func TestRepositoryRemoval_DraftsFromOtherReposUnaffected(t *testing.T) {
	repoStore := NewMockRepositoryRemovalStore()
	webhookDeleter := NewMockGitHubWebhookDeleter()
	draftStore := NewMockDraftPreserver()

	userID := "user-456"
	repoID1 := "repo-to-delete"
	repoID2 := "repo-to-keep"

	repo1 := &Repository{
		ID:        repoID1,
		UserID:    userID,
		GitHubURL: "https://github.com/testowner/repo1",
		CreatedAt: time.Now(),
	}
	repo2 := &Repository{
		ID:        repoID2,
		UserID:    userID,
		GitHubURL: "https://github.com/testowner/repo2",
		CreatedAt: time.Now(),
	}
	repoStore.AddRepository(repo1)
	repoStore.AddRepository(repo2)

	// Add drafts for both repos
	draftStore.AddDraft(&RemovalDraft{
		ID:           "draft-repo1",
		UserID:       userID,
		RepositoryID: &repoID1,
		Content:      "Draft for repo 1",
		Status:       "draft",
		CreatedAt:    time.Now(),
	})
	draftStore.AddDraft(&RemovalDraft{
		ID:           "draft-repo2",
		UserID:       userID,
		RepositoryID: &repoID2,
		Content:      "Draft for repo 2",
		Status:       "draft",
		CreatedAt:    time.Now(),
	})

	// Remove only repo1
	removeRepository(context.Background(), repoStore, webhookDeleter, draftStore, repoID1, "")

	// Repo2's draft should still be associated with repo2
	draftsForRepo2, _ := draftStore.GetDraftsByRepository(context.Background(), repoID2)
	if len(draftsForRepo2) != 1 {
		t.Errorf("Expected 1 draft still associated with repo2, got %d", len(draftsForRepo2))
	}

	if len(draftsForRepo2) > 0 && *draftsForRepo2[0].RepositoryID != repoID2 {
		t.Error("Repo2's draft should still be associated with repo2")
	}
}

// =============================================================================
// Test: Combined Webhook + Draft Behavior
// =============================================================================

// TestRepositoryRemoval_FullFlow tests the complete removal flow with both
// webhook cleanup and draft preservation.
func TestRepositoryRemoval_FullFlow(t *testing.T) {
	repoStore := NewMockRepositoryRemovalStore()
	webhookDeleter := NewMockGitHubWebhookDeleter()
	draftStore := NewMockDraftPreserver()

	repoID := "repo-123"
	userID := "user-456"
	webhookID := int64(12345)

	repo := &Repository{
		ID:        repoID,
		UserID:    userID,
		GitHubURL: "https://github.com/testowner/testrepo",
		WebhookID: &webhookID,
		CreatedAt: time.Now(),
	}
	repoStore.AddRepository(repo)

	// Add drafts
	draftStore.AddDraft(&RemovalDraft{
		ID:           "draft-1",
		UserID:       userID,
		RepositoryID: &repoID,
		Content:      "Draft content",
		Status:       "draft",
		CreatedAt:    time.Now(),
	})

	// Execute full removal
	result := removeRepository(context.Background(), repoStore, webhookDeleter, draftStore, repoID, "valid-token")

	// All aspects should succeed
	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if !result.RepoDeleted {
		t.Error("Expected RepoDeleted to be true")
	}
	if !result.WebhookDeleted {
		t.Error("Expected WebhookDeleted to be true")
	}
	if result.DraftsOrphaned != 1 {
		t.Errorf("Expected DraftsOrphaned to be 1, got %d", result.DraftsOrphaned)
	}
	if result.Warning != "" {
		t.Errorf("Expected no warning, got: %s", result.Warning)
	}
}

// TestRepositoryRemoval_RepoNotFound tests behavior when repository doesn't exist.
func TestRepositoryRemoval_RepoNotFound(t *testing.T) {
	repoStore := NewMockRepositoryRemovalStore()
	webhookDeleter := NewMockGitHubWebhookDeleter()
	draftStore := NewMockDraftPreserver()

	result := removeRepository(context.Background(), repoStore, webhookDeleter, draftStore, "non-existent-repo", "")

	if result.Success {
		t.Error("Expected Success to be false for non-existent repo")
	}
	if result.RepoDeleted {
		t.Error("Expected RepoDeleted to be false")
	}
}

// =============================================================================
// Helper function (to be implemented in repository.go or a service)
// This is the function being tested - currently stubbed for TDD red phase
// =============================================================================

// GitHubWebhookDeleter interface for deleting webhooks from GitHub
type GitHubWebhookDeleter interface {
	DeleteWebhook(ctx context.Context, owner, repo string, webhookID int64) error
}

// DraftPreserver interface for orphaning drafts during repository removal
type DraftPreserver interface {
	OrphanDraftsByRepository(ctx context.Context, repositoryID string) error
	GetDraftsByRepository(ctx context.Context, repositoryID string) ([]*RemovalDraft, error)
	GetOrphanedDrafts(ctx context.Context, userID string) ([]*RemovalDraft, error)
}

// RepositoryRemovalStore interface for repository operations during removal
type RepositoryRemovalStore interface {
	GetRepositoryByID(ctx context.Context, repoID string) (*Repository, error)
	DeleteRepository(ctx context.Context, repoID string) error
}

// removeRepository orchestrates the repository removal process
// - Attempts to delete webhook from GitHub (best effort)
// - Orphans associated drafts (preserves them)
// - Deletes repository from database
func removeRepository(
	ctx context.Context,
	repoStore RepositoryRemovalStore,
	webhookDeleter GitHubWebhookDeleter,
	draftPreserver DraftPreserver,
	repoID string,
	githubToken string,
) RepositoryRemovalResult {
	result := RepositoryRemovalResult{}

	// Get repository
	repo, err := repoStore.GetRepositoryByID(ctx, repoID)
	if err != nil || repo == nil {
		result.Success = false
		return result
	}

	// Step 1: Try to delete webhook from GitHub (best effort)
	if repo.WebhookID != nil && webhookDeleter != nil {
		owner, repoName := parseGitHubURL(repo.GitHubURL)
		err := webhookDeleter.DeleteWebhook(ctx, owner, repoName, *repo.WebhookID)
		if err != nil {
			if errors.Is(err, ErrGitHubAuthExpired) {
				result.Warning = "Webhook may still exist on GitHub. You can remove it manually in repo settings."
			} else if errors.Is(err, ErrGitHubRateLimited) {
				result.Warning = "GitHub rate limited. Webhook may still exist on GitHub."
			} else if !errors.Is(err, ErrGitHubWebhookNotFound) {
				result.Warning = "Could not delete webhook from GitHub."
			}
			// Note: webhook not found is not an error - it's already gone
		} else {
			result.WebhookDeleted = true
		}
	}

	// Step 2: Orphan drafts (preserve them)
	if draftPreserver != nil {
		drafts, _ := draftPreserver.GetDraftsByRepository(ctx, repoID)
		result.DraftsOrphaned = len(drafts)
		draftPreserver.OrphanDraftsByRepository(ctx, repoID)
	}

	// Step 3: Delete repository from database
	err = repoStore.DeleteRepository(ctx, repoID)
	if err != nil {
		result.Success = false
		return result
	}
	result.RepoDeleted = true
	result.Success = true

	return result
}

// parseGitHubURL extracts owner and repo from a GitHub URL
func parseGitHubURL(githubURL string) (owner, repo string) {
	// Parse https://github.com/owner/repo
	// Remove protocol and host
	url := githubURL
	if len(url) > 19 && url[:19] == "https://github.com/" {
		url = url[19:]
	}

	// Split by /
	parts := splitPath(url)
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

// splitPath splits a path by /
func splitPath(path string) []string {
	var parts []string
	current := ""
	for _, c := range path {
		if c == '/' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
