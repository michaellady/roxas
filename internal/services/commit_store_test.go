package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// TB14: Commit Storage Service Tests (TDD - RED)
// =============================================================================

// Commit represents a git commit to be stored
type Commit struct {
	ID           string
	RepositoryID string
	CommitSHA    string
	GitHubURL    string
	Message      string
	Author       string
	Timestamp    time.Time
	CreatedAt    time.Time
}

// CommitStoreService defines the interface for commit persistence operations
type CommitStoreService interface {
	// Store saves a commit, returning the stored commit (existing if duplicate)
	Store(ctx context.Context, commit *Commit) (*Commit, error)

	// GetBySHA retrieves a commit by repository ID and SHA
	GetBySHA(ctx context.Context, repoID, sha string) (*Commit, error)
}

// =============================================================================
// Test: Store New Commit Returns Commit Object
// =============================================================================

func TestCommitStoreService_StoreNewCommit_ReturnsCommitObject(t *testing.T) {
	// This test verifies that storing a new commit returns the commit object
	// with a generated ID and CreatedAt timestamp

	store := NewCommitStoreService(nil) // Will fail - no implementation

	commit := &Commit{
		RepositoryID: uuid.New().String(),
		CommitSHA:    "abc123def456789012345678901234567890abcd",
		GitHubURL:    "https://github.com/test/repo/commit/abc123def456",
		Message:      "feat: add new feature",
		Author:       "Test Author",
		Timestamp:    time.Now().UTC(),
	}

	ctx := context.Background()
	result, err := store.Store(ctx, commit)

	if err != nil {
		t.Fatalf("Expected no error storing new commit, got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected commit result, got nil")
	}

	// Should have generated ID
	if result.ID == "" {
		t.Error("Expected generated ID, got empty string")
	}

	// Should preserve input fields
	if result.RepositoryID != commit.RepositoryID {
		t.Errorf("RepositoryID mismatch: got %s, want %s", result.RepositoryID, commit.RepositoryID)
	}

	if result.CommitSHA != commit.CommitSHA {
		t.Errorf("CommitSHA mismatch: got %s, want %s", result.CommitSHA, commit.CommitSHA)
	}

	if result.Message != commit.Message {
		t.Errorf("Message mismatch: got %s, want %s", result.Message, commit.Message)
	}

	if result.Author != commit.Author {
		t.Errorf("Author mismatch: got %s, want %s", result.Author, commit.Author)
	}

	// Should have CreatedAt set
	if result.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set, got zero time")
	}
}

// =============================================================================
// Test: Store Duplicate Commit Returns Existing (No Duplicate)
// =============================================================================

func TestCommitStoreService_StoreDuplicate_ReturnsExistingNoDuplicate(t *testing.T) {
	// This test verifies that storing a commit with same SHA + repo_id
	// returns the existing commit without creating a duplicate
	// (Tests UNIQUE constraint on repository_id + commit_sha)

	store := NewCommitStoreService(nil) // Will fail - no implementation

	repoID := uuid.New().String()
	sha := "abc123def456789012345678901234567890abcd"

	commit := &Commit{
		RepositoryID: repoID,
		CommitSHA:    sha,
		GitHubURL:    "https://github.com/test/repo/commit/abc123def456",
		Message:      "feat: original message",
		Author:       "Original Author",
		Timestamp:    time.Now().UTC(),
	}

	ctx := context.Background()

	// Store first commit
	first, err := store.Store(ctx, commit)
	if err != nil {
		t.Fatalf("Expected no error storing first commit, got: %v", err)
	}

	// Try to store duplicate (same SHA + repo)
	duplicateCommit := &Commit{
		RepositoryID: repoID,
		CommitSHA:    sha,
		GitHubURL:    "https://github.com/test/repo/commit/abc123def456",
		Message:      "feat: different message", // Different message
		Author:       "Different Author",        // Different author
		Timestamp:    time.Now().UTC(),
	}

	second, err := store.Store(ctx, duplicateCommit)
	if err != nil {
		t.Fatalf("Expected no error storing duplicate, got: %v", err)
	}

	// Should return the EXISTING commit, not create a new one
	if second.ID != first.ID {
		t.Errorf("Expected same ID for duplicate, got different: first=%s, second=%s", first.ID, second.ID)
	}

	// Should preserve ORIGINAL message (not the duplicate's)
	if second.Message != first.Message {
		t.Errorf("Expected original message preserved, got: %s, want: %s", second.Message, first.Message)
	}
}

// =============================================================================
// Test: Same SHA Different Repo Creates New Commit
// =============================================================================

func TestCommitStoreService_SameSHADifferentRepo_CreatesNewCommit(t *testing.T) {
	// This test verifies that the same SHA can be stored for different repos
	// (UNIQUE constraint is on repository_id + commit_sha, not just commit_sha)

	store := NewCommitStoreService(nil) // Will fail - no implementation

	sha := "abc123def456789012345678901234567890abcd"
	repo1ID := uuid.New().String()
	repo2ID := uuid.New().String()

	ctx := context.Background()

	// Store commit for repo1
	commit1 := &Commit{
		RepositoryID: repo1ID,
		CommitSHA:    sha,
		GitHubURL:    "https://github.com/user1/repo/commit/abc123",
		Message:      "feat: in repo1",
		Author:       "Author One",
		Timestamp:    time.Now().UTC(),
	}
	result1, err := store.Store(ctx, commit1)
	if err != nil {
		t.Fatalf("Expected no error storing commit in repo1, got: %v", err)
	}

	// Store commit with SAME SHA for repo2
	commit2 := &Commit{
		RepositoryID: repo2ID,
		CommitSHA:    sha, // Same SHA
		GitHubURL:    "https://github.com/user2/repo/commit/abc123",
		Message:      "feat: in repo2",
		Author:       "Author Two",
		Timestamp:    time.Now().UTC(),
	}
	result2, err := store.Store(ctx, commit2)
	if err != nil {
		t.Fatalf("Expected no error storing commit in repo2, got: %v", err)
	}

	// Should be DIFFERENT commits (different IDs)
	if result1.ID == result2.ID {
		t.Error("Expected different IDs for same SHA in different repos")
	}

	// Each should have correct repo ID
	if result1.RepositoryID != repo1ID {
		t.Errorf("Expected repo1ID, got %s", result1.RepositoryID)
	}
	if result2.RepositoryID != repo2ID {
		t.Errorf("Expected repo2ID, got %s", result2.RepositoryID)
	}
}

// =============================================================================
// Test: Missing Required Fields Returns Error
// =============================================================================

func TestCommitStoreService_MissingRequiredFields_ReturnsError(t *testing.T) {
	// This test verifies that missing required fields produce validation errors
	// before hitting the database

	store := NewCommitStoreService(nil) // Will fail - no implementation
	ctx := context.Background()

	tests := []struct {
		name   string
		commit *Commit
	}{
		{
			name: "missing repository_id",
			commit: &Commit{
				RepositoryID: "", // Empty
				CommitSHA:    "abc123def456789012345678901234567890abcd",
				GitHubURL:    "https://github.com/test/repo/commit/abc123",
				Message:      "test",
				Author:       "Test",
				Timestamp:    time.Now(),
			},
		},
		{
			name: "missing commit_sha",
			commit: &Commit{
				RepositoryID: uuid.New().String(),
				CommitSHA:    "", // Empty
				GitHubURL:    "https://github.com/test/repo/commit/abc123",
				Message:      "test",
				Author:       "Test",
				Timestamp:    time.Now(),
			},
		},
		{
			name: "missing github_url",
			commit: &Commit{
				RepositoryID: uuid.New().String(),
				CommitSHA:    "abc123def456789012345678901234567890abcd",
				GitHubURL:    "", // Empty
				Message:      "test",
				Author:       "Test",
				Timestamp:    time.Now(),
			},
		},
		{
			name: "missing timestamp",
			commit: &Commit{
				RepositoryID: uuid.New().String(),
				CommitSHA:    "abc123def456789012345678901234567890abcd",
				GitHubURL:    "https://github.com/test/repo/commit/abc123",
				Message:      "test",
				Author:       "Test",
				Timestamp:    time.Time{}, // Zero time
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.Store(ctx, tt.commit)

			if err == nil {
				t.Errorf("Expected error for %s, got nil", tt.name)
			}

			// Error should be a validation error
			if !errors.Is(err, ErrValidation) {
				t.Errorf("Expected ErrValidation, got: %v", err)
			}
		})
	}
}

// =============================================================================
// Test: GetBySHA Returns Stored Commit
// =============================================================================

func TestCommitStoreService_GetBySHA_ReturnsStoredCommit(t *testing.T) {
	// This test verifies that GetBySHA retrieves a previously stored commit

	store := NewCommitStoreService(nil) // Will fail - no implementation
	ctx := context.Background()

	repoID := uuid.New().String()
	sha := "abc123def456789012345678901234567890abcd"

	commit := &Commit{
		RepositoryID: repoID,
		CommitSHA:    sha,
		GitHubURL:    "https://github.com/test/repo/commit/abc123",
		Message:      "feat: test feature",
		Author:       "Test Author",
		Timestamp:    time.Now().UTC(),
	}

	// Store commit
	stored, err := store.Store(ctx, commit)
	if err != nil {
		t.Fatalf("Failed to store commit: %v", err)
	}

	// Retrieve by SHA
	retrieved, err := store.GetBySHA(ctx, repoID, sha)
	if err != nil {
		t.Fatalf("Failed to get commit by SHA: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected commit, got nil")
	}

	// Should match stored commit
	if retrieved.ID != stored.ID {
		t.Errorf("ID mismatch: got %s, want %s", retrieved.ID, stored.ID)
	}

	if retrieved.Message != commit.Message {
		t.Errorf("Message mismatch: got %s, want %s", retrieved.Message, commit.Message)
	}
}

// =============================================================================
// Test: GetBySHA Returns Nil for Non-Existent
// =============================================================================

func TestCommitStoreService_GetBySHA_ReturnsNilForNonExistent(t *testing.T) {
	// This test verifies that GetBySHA returns nil (not error) for non-existent commits

	store := NewCommitStoreService(nil) // Will fail - no implementation
	ctx := context.Background()

	retrieved, err := store.GetBySHA(ctx, uuid.New().String(), "nonexistent123456789012345678901234567890")

	if err != nil {
		t.Fatalf("Expected no error for non-existent commit, got: %v", err)
	}

	if retrieved != nil {
		t.Error("Expected nil for non-existent commit, got non-nil")
	}
}

// =============================================================================
// Sentinel Errors
// =============================================================================

// ErrValidation is returned when commit data fails validation
var ErrValidation = errors.New("validation error")

// =============================================================================
// Constructor (placeholder - will be implemented in TB15)
// =============================================================================

// NewCommitStoreService creates a new commit store service
// This is a placeholder that will fail - implementation is TB15
func NewCommitStoreService(db interface{}) CommitStoreService {
	// TB15 will implement this
	panic("NewCommitStoreService not implemented - see TB15")
}
