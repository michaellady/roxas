package services

import (
	"context"
	"errors"
	"testing"
	"time"
)

// =============================================================================
// DraftPostCreator Tests (TDD - TB-POST-01)
// =============================================================================

// MockCommitLookup implements CommitLookup for testing
type MockCommitLookup struct {
	commits map[string]*Commit
	err     error
}

func (m *MockCommitLookup) GetCommitByID(ctx context.Context, id string) (*Commit, error) {
	if m.err != nil {
		return nil, m.err
	}
	commit, ok := m.commits[id]
	if !ok {
		return nil, nil
	}
	return commit, nil
}

// MockPostGenerator implements PostGeneratorService for testing
type MockPostGenerator struct {
	content string
	err     error
}

func (m *MockPostGenerator) Generate(ctx context.Context, platform string, commit *Commit) (*GeneratedPost, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &GeneratedPost{
		Platform: platform,
		Content:  m.content,
		CommitID: commit.ID,
	}, nil
}

// MockDraftStore implements DraftStore for testing
type MockDraftStore struct {
	posts   []*DraftPost
	nextID  string
	err     error
	created *DraftPost
}

func (m *MockDraftStore) CreateDraftPost(ctx context.Context, commitID, platform, content string) (*DraftPost, error) {
	if m.err != nil {
		return nil, m.err
	}
	post := &DraftPost{
		ID:        m.nextID,
		CommitID:  commitID,
		Platform:  platform,
		Content:   content,
		Status:    DraftStatusDraft,
		CreatedAt: time.Now(),
	}
	m.created = post
	m.posts = append(m.posts, post)
	return post, nil
}

// =============================================================================
// Test Cases
// =============================================================================

func TestDraftPostCreator_CreateDraft_Success(t *testing.T) {
	// Setup mocks
	commit := &Commit{
		ID:        "commit-123",
		GitHubURL: "https://github.com/owner/repo/commit/abc123",
		Message:   "Add new feature",
		Author:    "developer",
	}
	commitLookup := &MockCommitLookup{
		commits: map[string]*Commit{commit.ID: commit},
	}
	generator := &MockPostGenerator{
		content: "Exciting update! We just shipped a new feature...",
	}
	store := &MockDraftStore{
		nextID: "post-456",
	}

	// Create the DraftPostCreator
	creator := NewDraftPostCreator(commitLookup, generator, store)

	// Execute
	draft, err := creator.CreateDraft(context.Background(), "commit-123", PlatformLinkedIn)

	// Verify
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if draft == nil {
		t.Fatal("expected draft post, got nil")
	}
	if draft.ID != "post-456" {
		t.Errorf("expected ID 'post-456', got '%s'", draft.ID)
	}
	if draft.CommitID != "commit-123" {
		t.Errorf("expected CommitID 'commit-123', got '%s'", draft.CommitID)
	}
	if draft.Platform != PlatformLinkedIn {
		t.Errorf("expected Platform 'linkedin', got '%s'", draft.Platform)
	}
	if draft.Content != "Exciting update! We just shipped a new feature..." {
		t.Errorf("unexpected Content: '%s'", draft.Content)
	}
	if draft.Status != DraftStatusDraft {
		t.Errorf("expected Status 'draft', got '%s'", draft.Status)
	}
}

func TestDraftPostCreator_CreateDraft_CommitNotFound(t *testing.T) {
	// Setup mocks with no commits
	commitLookup := &MockCommitLookup{
		commits: map[string]*Commit{},
	}
	generator := &MockPostGenerator{}
	store := &MockDraftStore{}

	creator := NewDraftPostCreator(commitLookup, generator, store)

	// Execute
	draft, err := creator.CreateDraft(context.Background(), "nonexistent", PlatformLinkedIn)

	// Verify
	if err == nil {
		t.Fatal("expected error for nonexistent commit")
	}
	if !errors.Is(err, ErrCommitNotFound) {
		t.Errorf("expected ErrCommitNotFound, got: %v", err)
	}
	if draft != nil {
		t.Error("expected nil draft for error case")
	}
}

func TestDraftPostCreator_CreateDraft_UnsupportedPlatform(t *testing.T) {
	commit := &Commit{ID: "commit-123"}
	commitLookup := &MockCommitLookup{
		commits: map[string]*Commit{commit.ID: commit},
	}
	generator := &MockPostGenerator{}
	store := &MockDraftStore{}

	creator := NewDraftPostCreator(commitLookup, generator, store)

	// Execute with unsupported platform
	draft, err := creator.CreateDraft(context.Background(), "commit-123", "tiktok")

	// Verify
	if err == nil {
		t.Fatal("expected error for unsupported platform")
	}
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("expected ErrUnsupportedPlatform, got: %v", err)
	}
	if draft != nil {
		t.Error("expected nil draft for error case")
	}
}

func TestDraftPostCreator_CreateDraft_CommitLookupError(t *testing.T) {
	dbErr := errors.New("database connection failed")
	commitLookup := &MockCommitLookup{
		err: dbErr,
	}
	generator := &MockPostGenerator{}
	store := &MockDraftStore{}

	creator := NewDraftPostCreator(commitLookup, generator, store)

	// Execute
	draft, err := creator.CreateDraft(context.Background(), "commit-123", PlatformLinkedIn)

	// Verify
	if err == nil {
		t.Fatal("expected error from commit lookup")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped db error, got: %v", err)
	}
	if draft != nil {
		t.Error("expected nil draft for error case")
	}
}

func TestDraftPostCreator_CreateDraft_GenerationError(t *testing.T) {
	commit := &Commit{ID: "commit-123"}
	commitLookup := &MockCommitLookup{
		commits: map[string]*Commit{commit.ID: commit},
	}
	genErr := errors.New("AI service unavailable")
	generator := &MockPostGenerator{
		err: genErr,
	}
	store := &MockDraftStore{}

	creator := NewDraftPostCreator(commitLookup, generator, store)

	// Execute
	draft, err := creator.CreateDraft(context.Background(), "commit-123", PlatformLinkedIn)

	// Verify
	if err == nil {
		t.Fatal("expected error from generation")
	}
	if !errors.Is(err, genErr) {
		t.Errorf("expected wrapped generation error, got: %v", err)
	}
	if draft != nil {
		t.Error("expected nil draft for error case")
	}
}

func TestDraftPostCreator_CreateDraft_StoreError(t *testing.T) {
	commit := &Commit{ID: "commit-123"}
	commitLookup := &MockCommitLookup{
		commits: map[string]*Commit{commit.ID: commit},
	}
	generator := &MockPostGenerator{
		content: "Generated content",
	}
	storeErr := errors.New("failed to insert")
	store := &MockDraftStore{
		err: storeErr,
	}

	creator := NewDraftPostCreator(commitLookup, generator, store)

	// Execute
	draft, err := creator.CreateDraft(context.Background(), "commit-123", PlatformLinkedIn)

	// Verify
	if err == nil {
		t.Fatal("expected error from store")
	}
	if !errors.Is(err, storeErr) {
		t.Errorf("expected wrapped store error, got: %v", err)
	}
	if draft != nil {
		t.Error("expected nil draft for error case")
	}
}

func TestDraftPostCreator_CreateDraft_AllPlatforms(t *testing.T) {
	platforms := []string{
		PlatformLinkedIn,
		PlatformTwitter,
		PlatformInstagram,
		PlatformYouTube,
	}

	for _, platform := range platforms {
		t.Run(platform, func(t *testing.T) {
			commit := &Commit{ID: "commit-123"}
			commitLookup := &MockCommitLookup{
				commits: map[string]*Commit{commit.ID: commit},
			}
			generator := &MockPostGenerator{
				content: "Content for " + platform,
			}
			store := &MockDraftStore{
				nextID: "post-" + platform,
			}

			creator := NewDraftPostCreator(commitLookup, generator, store)

			draft, err := creator.CreateDraft(context.Background(), "commit-123", platform)

			if err != nil {
				t.Fatalf("expected no error for %s, got: %v", platform, err)
			}
			if draft.Platform != platform {
				t.Errorf("expected platform '%s', got '%s'", platform, draft.Platform)
			}
		})
	}
}

func TestDraftPostCreator_CreateDraft_EmptyCommitID(t *testing.T) {
	commitLookup := &MockCommitLookup{}
	generator := &MockPostGenerator{}
	store := &MockDraftStore{}

	creator := NewDraftPostCreator(commitLookup, generator, store)

	// Execute with empty commit ID
	draft, err := creator.CreateDraft(context.Background(), "", PlatformLinkedIn)

	// Verify
	if err == nil {
		t.Fatal("expected error for empty commit ID")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
	if draft != nil {
		t.Error("expected nil draft for error case")
	}
}

func TestDraftPostCreator_CreateDraft_EmptyPlatform(t *testing.T) {
	commit := &Commit{ID: "commit-123"}
	commitLookup := &MockCommitLookup{
		commits: map[string]*Commit{commit.ID: commit},
	}
	generator := &MockPostGenerator{}
	store := &MockDraftStore{}

	creator := NewDraftPostCreator(commitLookup, generator, store)

	// Execute with empty platform
	draft, err := creator.CreateDraft(context.Background(), "commit-123", "")

	// Verify
	if err == nil {
		t.Fatal("expected error for empty platform")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
	if draft != nil {
		t.Error("expected nil draft for error case")
	}
}
