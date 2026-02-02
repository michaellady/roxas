package handlers

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MockRepositoryStore is an in-memory implementation of RepositoryStore for testing.
// Exported for use in property tests and integration tests.
type MockRepositoryStore struct {
	mu    sync.Mutex
	repos map[string]*Repository
}

// NewMockRepositoryStore creates a new mock repository store
func NewMockRepositoryStore() *MockRepositoryStore {
	return &MockRepositoryStore{
		repos: make(map[string]*Repository),
	}
}

// CreateRepository creates a new repository in the mock store
func (m *MockRepositoryStore) CreateRepository(ctx context.Context, userID, githubURL, webhookSecret string) (*Repository, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicate (same user + same URL)
	for _, r := range m.repos {
		if r.UserID == userID && r.GitHubURL == githubURL {
			return nil, ErrDuplicateRepository
		}
	}

	repo := &Repository{
		ID:            uuid.New().String(),
		UserID:        userID,
		GitHubURL:     githubURL,
		WebhookSecret: webhookSecret,
		CreatedAt:     time.Now(),
	}

	m.repos[repo.ID] = repo
	return repo, nil
}

// GetRepositoryByUserAndURL retrieves a repository by user ID and GitHub URL
func (m *MockRepositoryStore) GetRepositoryByUserAndURL(ctx context.Context, userID, githubURL string) (*Repository, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, r := range m.repos {
		if r.UserID == userID && r.GitHubURL == githubURL {
			return r, nil
		}
	}
	return nil, nil
}

// ListRepositoriesByUser returns all repositories for a user
func (m *MockRepositoryStore) ListRepositoriesByUser(ctx context.Context, userID string) ([]*Repository, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []*Repository
	for _, r := range m.repos {
		if r.UserID == userID {
			result = append(result, r)
		}
	}
	return result, nil
}
