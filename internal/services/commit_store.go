package services

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// Types and Interface
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

// ErrValidation is returned when commit data fails validation
var ErrValidation = errors.New("validation error")

// =============================================================================
// In-Memory Implementation (for unit tests and development)
// =============================================================================

// InMemoryCommitStore is an in-memory implementation of CommitStoreService
// Used for unit tests and can be swapped with PostgresCommitStore for production
type InMemoryCommitStore struct {
	mu      sync.RWMutex
	commits map[string]*Commit // key: repoID:sha
}

// NewInMemoryCommitStore creates a new in-memory commit store
func NewInMemoryCommitStore() *InMemoryCommitStore {
	return &InMemoryCommitStore{
		commits: make(map[string]*Commit),
	}
}

// Store saves a commit, returning the stored commit (existing if duplicate)
func (s *InMemoryCommitStore) Store(ctx context.Context, commit *Commit) (*Commit, error) {
	// Validate required fields before storing
	if err := validateCommit(commit); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for existing commit (same repo + SHA)
	key := makeKey(commit.RepositoryID, commit.CommitSHA)
	if existing, ok := s.commits[key]; ok {
		// Return existing commit (deduplication)
		return existing, nil
	}

	// Generate ID and set CreatedAt for new commit
	stored := &Commit{
		ID:           uuid.New().String(),
		RepositoryID: commit.RepositoryID,
		CommitSHA:    commit.CommitSHA,
		GitHubURL:    commit.GitHubURL,
		Message:      commit.Message,
		Author:       commit.Author,
		Timestamp:    commit.Timestamp,
		CreatedAt:    time.Now().UTC(),
	}

	s.commits[key] = stored
	return stored, nil
}

// GetBySHA retrieves a commit by repository ID and SHA
func (s *InMemoryCommitStore) GetBySHA(ctx context.Context, repoID, sha string) (*Commit, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := makeKey(repoID, sha)
	if commit, ok := s.commits[key]; ok {
		return commit, nil
	}
	return nil, nil // Not found returns nil, nil (not an error)
}

// makeKey creates a composite key for the commit map
func makeKey(repoID, sha string) string {
	return repoID + ":" + sha
}

// validateCommit validates required fields before storing
func validateCommit(commit *Commit) error {
	if commit.RepositoryID == "" {
		return fmt.Errorf("%w: repository_id is required", ErrValidation)
	}
	if commit.CommitSHA == "" {
		return fmt.Errorf("%w: commit_sha is required", ErrValidation)
	}
	if commit.GitHubURL == "" {
		return fmt.Errorf("%w: github_url is required", ErrValidation)
	}
	if commit.Timestamp.IsZero() {
		return fmt.Errorf("%w: timestamp is required", ErrValidation)
	}
	return nil
}
