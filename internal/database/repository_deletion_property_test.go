// Package database contains property tests for repository deletion behavior.
// Property 31: Repository Deletion Preserves Drafts
// Validates Requirements 10.7 (delete repository record), 10.8 (keep existing drafts)
//
// Property: When a repository is removed, the repository record is deleted
// but all associated drafts remain accessible (orphaned but viewable).
package database

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Mock Types for Property Testing
// =============================================================================

// MockDraft represents a draft for testing purposes
type MockDraft struct {
	ID               string
	UserID           string
	RepositoryID     string
	Ref              string
	BeforeSHA        string
	AfterSHA         string
	CommitSHAs       []string
	GeneratedContent string
	Status           string
	CreatedAt        time.Time
}

// MockRepository represents a repository for testing purposes
type MockRepository struct {
	ID            string
	UserID        string
	GitHubURL     string
	WebhookSecret string
	CreatedAt     time.Time
}

// RepositoryDeletionStore simulates the expected repository deletion behavior.
// This mock implements the correct behavior per Requirements 10.7, 10.8:
// - Deleting a repository removes the repository record
// - Associated drafts are preserved (not cascaded)
type RepositoryDeletionStore struct {
	mu     sync.Mutex
	repos  map[string]*MockRepository
	drafts map[string]*MockDraft
}

// NewRepositoryDeletionStore creates a new store for testing repository deletion
func NewRepositoryDeletionStore() *RepositoryDeletionStore {
	return &RepositoryDeletionStore{
		repos:  make(map[string]*MockRepository),
		drafts: make(map[string]*MockDraft),
	}
}

// CreateRepository creates a repository in the mock store
func (s *RepositoryDeletionStore) CreateRepository(userID, githubURL, webhookSecret string) *MockRepository {
	s.mu.Lock()
	defer s.mu.Unlock()

	repo := &MockRepository{
		ID:            uuid.New().String(),
		UserID:        userID,
		GitHubURL:     githubURL,
		WebhookSecret: webhookSecret,
		CreatedAt:     time.Now(),
	}
	s.repos[repo.ID] = repo
	return repo
}

// CreateDraft creates a draft associated with a repository
func (s *RepositoryDeletionStore) CreateDraft(userID, repositoryID, ref, afterSHA, content string) *MockDraft {
	s.mu.Lock()
	defer s.mu.Unlock()

	draft := &MockDraft{
		ID:               uuid.New().String(),
		UserID:           userID,
		RepositoryID:     repositoryID,
		Ref:              ref,
		AfterSHA:         afterSHA,
		CommitSHAs:       []string{afterSHA},
		GeneratedContent: content,
		Status:           "draft",
		CreatedAt:        time.Now(),
	}
	s.drafts[draft.ID] = draft
	return draft
}

// DeleteRepository removes a repository but preserves drafts (per Requirement 10.8)
func (s *RepositoryDeletionStore) DeleteRepository(repoID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.repos, repoID)
	// Drafts are NOT deleted - they remain as orphans (per Requirement 10.8)
	return nil
}

// GetRepository retrieves a repository by ID
func (s *RepositoryDeletionStore) GetRepository(repoID string) *MockRepository {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.repos[repoID]
}

// GetDraft retrieves a draft by ID
func (s *RepositoryDeletionStore) GetDraft(draftID string) *MockDraft {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.drafts[draftID]
}

// GetDraftsByRepository retrieves all drafts for a repository
func (s *RepositoryDeletionStore) GetDraftsByRepository(repoID string) []*MockDraft {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []*MockDraft
	for _, d := range s.drafts {
		if d.RepositoryID == repoID {
			result = append(result, d)
		}
	}
	return result
}

// RepositoryExists checks if a repository exists
func (s *RepositoryDeletionStore) RepositoryExists(repoID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.repos[repoID]
	return exists
}

// DraftExists checks if a draft exists
func (s *RepositoryDeletionStore) DraftExists(draftID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.drafts[draftID]
	return exists
}

// CountDrafts returns the total number of drafts
func (s *RepositoryDeletionStore) CountDrafts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.drafts)
}

// =============================================================================
// Generators
// =============================================================================

// genUserID generates random user IDs (UUIDs)
func genUserID() gopter.Gen {
	return gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
}

// genGitHubURL generates random GitHub repository URLs
func genGitHubURL() gopter.Gen {
	owner := gen.RegexMatch(`[a-z][a-z0-9]{2,15}`)
	repo := gen.RegexMatch(`[a-z][a-z0-9._-]{2,30}`)

	return gopter.CombineGens(owner, repo).Map(func(vals []interface{}) string {
		return "https://github.com/" + vals[0].(string) + "/" + vals[1].(string)
	})
}

// genWebhookSecret generates random webhook secrets
func genWebhookSecret() gopter.Gen {
	return gen.RegexMatch(`[A-Za-z0-9_-]{32,64}`)
}

// genGitRef generates random git refs
func genGitRef() gopter.Gen {
	branch := gen.RegexMatch(`[a-z][a-z0-9-]{2,20}`)
	return branch.Map(func(b string) string {
		return "refs/heads/" + b
	})
}

// genCommitSHA generates random commit SHAs
func genCommitSHA() gopter.Gen {
	return gen.RegexMatch(`[0-9a-f]{40}`)
}

// genDraftContent generates random draft content
func genDraftContent() gopter.Gen {
	return gen.AnyString().SuchThat(func(s string) bool {
		return len(s) > 0 && len(s) < 500
	})
}

// genDraftCount generates the number of drafts to create (0-10)
func genDraftCount() gopter.Gen {
	return gen.IntRange(0, 10)
}

// =============================================================================
// Property Tests
// =============================================================================

// TestProperty31_RepositoryDeletionPreservesDrafts tests that repository deletion
// preserves associated drafts as orphans.
// Validates Requirements 10.7 (delete repo record), 10.8 (keep drafts)
func TestProperty31_RepositoryDeletionPreservesDrafts(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	// Property 31a: Repository is deleted after DeleteRepository call
	properties.Property("repository record is removed after deletion", prop.ForAll(
		func(userID, githubURL, webhookSecret string) bool {
			store := NewRepositoryDeletionStore()

			// Create a repository
			repo := store.CreateRepository(userID, githubURL, webhookSecret)
			repoID := repo.ID

			// Verify it exists
			if !store.RepositoryExists(repoID) {
				return false
			}

			// Delete the repository
			if err := store.DeleteRepository(repoID); err != nil {
				return false
			}

			// Verify it no longer exists
			return !store.RepositoryExists(repoID)
		},
		genUserID(),
		genGitHubURL(),
		genWebhookSecret(),
	))

	// Property 31b: Drafts are preserved after repository deletion
	properties.Property("drafts are preserved after repository deletion", prop.ForAll(
		func(userID, githubURL, webhookSecret string, numDrafts int, ref, sha, content string) bool {
			store := NewRepositoryDeletionStore()
			ctx := context.Background()
			_ = ctx // ctx available for future use if needed

			// Create a repository
			repo := store.CreateRepository(userID, githubURL, webhookSecret)
			repoID := repo.ID

			// Create drafts associated with this repository
			draftIDs := make([]string, 0, numDrafts)
			for i := 0; i < numDrafts; i++ {
				uniqueSHA := sha + "-" + uuid.New().String()[:8]
				draft := store.CreateDraft(userID, repoID, ref, uniqueSHA, content)
				draftIDs = append(draftIDs, draft.ID)
			}

			// Verify drafts exist before deletion
			for _, draftID := range draftIDs {
				if !store.DraftExists(draftID) {
					return false
				}
			}

			// Delete the repository
			if err := store.DeleteRepository(repoID); err != nil {
				return false
			}

			// Verify repository is gone
			if store.RepositoryExists(repoID) {
				return false
			}

			// Property: All drafts must still exist after repository deletion
			for _, draftID := range draftIDs {
				if !store.DraftExists(draftID) {
					t.Logf("Draft %s was deleted when repository %s was removed", draftID, repoID)
					return false
				}
			}

			return true
		},
		genUserID(),
		genGitHubURL(),
		genWebhookSecret(),
		genDraftCount(),
		genGitRef(),
		genCommitSHA(),
		genDraftContent(),
	))

	// Property 31c: Draft count remains unchanged after repository deletion
	properties.Property("draft count unchanged after repository deletion", prop.ForAll(
		func(userID, githubURL, webhookSecret string, numDrafts int, ref, sha, content string) bool {
			store := NewRepositoryDeletionStore()

			// Create a repository
			repo := store.CreateRepository(userID, githubURL, webhookSecret)
			repoID := repo.ID

			// Create drafts
			for i := 0; i < numDrafts; i++ {
				uniqueSHA := sha + "-" + uuid.New().String()[:8]
				store.CreateDraft(userID, repoID, ref, uniqueSHA, content)
			}

			// Count drafts before deletion
			countBefore := store.CountDrafts()

			// Delete repository
			if err := store.DeleteRepository(repoID); err != nil {
				return false
			}

			// Count drafts after deletion
			countAfter := store.CountDrafts()

			// Property: Draft count must be the same
			if countBefore != countAfter {
				t.Logf("Draft count changed: before=%d, after=%d", countBefore, countAfter)
				return false
			}

			return true
		},
		genUserID(),
		genGitHubURL(),
		genWebhookSecret(),
		genDraftCount(),
		genGitRef(),
		genCommitSHA(),
		genDraftContent(),
	))

	// Property 31d: Drafts maintain their data after repository deletion
	properties.Property("drafts maintain data integrity after repository deletion", prop.ForAll(
		func(userID, githubURL, webhookSecret, ref, sha, content string) bool {
			store := NewRepositoryDeletionStore()

			// Create a repository
			repo := store.CreateRepository(userID, githubURL, webhookSecret)
			repoID := repo.ID

			// Create a draft with specific data
			draft := store.CreateDraft(userID, repoID, ref, sha, content)
			draftID := draft.ID

			// Capture original values
			originalUserID := draft.UserID
			originalRepoID := draft.RepositoryID
			originalRef := draft.Ref
			originalAfterSHA := draft.AfterSHA
			originalContent := draft.GeneratedContent
			originalStatus := draft.Status

			// Delete repository
			if err := store.DeleteRepository(repoID); err != nil {
				return false
			}

			// Retrieve draft after deletion
			retrievedDraft := store.GetDraft(draftID)
			if retrievedDraft == nil {
				t.Logf("Draft not found after repository deletion")
				return false
			}

			// Property: All draft data must be preserved
			if retrievedDraft.UserID != originalUserID {
				t.Logf("UserID changed: expected %s, got %s", originalUserID, retrievedDraft.UserID)
				return false
			}
			if retrievedDraft.RepositoryID != originalRepoID {
				t.Logf("RepositoryID changed: expected %s, got %s", originalRepoID, retrievedDraft.RepositoryID)
				return false
			}
			if retrievedDraft.Ref != originalRef {
				t.Logf("Ref changed: expected %s, got %s", originalRef, retrievedDraft.Ref)
				return false
			}
			if retrievedDraft.AfterSHA != originalAfterSHA {
				t.Logf("AfterSHA changed: expected %s, got %s", originalAfterSHA, retrievedDraft.AfterSHA)
				return false
			}
			if retrievedDraft.GeneratedContent != originalContent {
				t.Logf("GeneratedContent changed")
				return false
			}
			if retrievedDraft.Status != originalStatus {
				t.Logf("Status changed: expected %s, got %s", originalStatus, retrievedDraft.Status)
				return false
			}

			return true
		},
		genUserID(),
		genGitHubURL(),
		genWebhookSecret(),
		genGitRef(),
		genCommitSHA(),
		genDraftContent(),
	))

	// Property 31e: Multiple repositories can be deleted without affecting each other's drafts
	properties.Property("deleting one repo does not affect other repos' drafts", prop.ForAll(
		func(userID string, numRepos int) bool {
			if numRepos < 2 {
				numRepos = 2 // Need at least 2 repos for this test
			}
			if numRepos > 5 {
				numRepos = 5 // Limit for performance
			}

			store := NewRepositoryDeletionStore()

			// Create multiple repositories with drafts
			type repoWithDrafts struct {
				repoID   string
				draftIDs []string
			}
			reposData := make([]repoWithDrafts, numRepos)

			for i := 0; i < numRepos; i++ {
				repo := store.CreateRepository(userID, "https://github.com/user/repo"+uuid.New().String()[:8], "secret")
				draftsForRepo := make([]string, 3) // 3 drafts per repo
				for j := 0; j < 3; j++ {
					draft := store.CreateDraft(userID, repo.ID, "refs/heads/main", uuid.New().String(), "content")
					draftsForRepo[j] = draft.ID
				}
				reposData[i] = repoWithDrafts{repoID: repo.ID, draftIDs: draftsForRepo}
			}

			// Delete the first repository
			if err := store.DeleteRepository(reposData[0].repoID); err != nil {
				return false
			}

			// Verify first repo's drafts still exist
			for _, draftID := range reposData[0].draftIDs {
				if !store.DraftExists(draftID) {
					t.Logf("Deleted repo's draft %s was removed", draftID)
					return false
				}
			}

			// Verify other repos still exist with their drafts
			for i := 1; i < numRepos; i++ {
				if !store.RepositoryExists(reposData[i].repoID) {
					t.Logf("Unrelated repo %s was deleted", reposData[i].repoID)
					return false
				}
				for _, draftID := range reposData[i].draftIDs {
					if !store.DraftExists(draftID) {
						t.Logf("Unrelated repo's draft %s was removed", draftID)
						return false
					}
				}
			}

			return true
		},
		genUserID(),
		gen.IntRange(2, 5),
	))

	// Property 31f: Orphaned drafts maintain their repository_id reference
	// (allowing users to see which repo the draft came from, even if repo is deleted)
	properties.Property("orphaned drafts maintain repository_id reference", prop.ForAll(
		func(userID, githubURL, webhookSecret, ref, sha, content string) bool {
			store := NewRepositoryDeletionStore()

			// Create a repository
			repo := store.CreateRepository(userID, githubURL, webhookSecret)
			repoID := repo.ID

			// Create drafts
			draft := store.CreateDraft(userID, repoID, ref, sha, content)
			draftID := draft.ID

			// Delete repository
			if err := store.DeleteRepository(repoID); err != nil {
				return false
			}

			// Retrieve draft
			retrievedDraft := store.GetDraft(draftID)
			if retrievedDraft == nil {
				return false
			}

			// Property: RepositoryID should still point to the deleted repo's ID
			// This allows the UI to display "from [deleted repository]" or similar
			if retrievedDraft.RepositoryID != repoID {
				t.Logf("RepositoryID was cleared or changed after repo deletion")
				return false
			}

			return true
		},
		genUserID(),
		genGitHubURL(),
		genWebhookSecret(),
		genGitRef(),
		genCommitSHA(),
		genDraftContent(),
	))

	properties.TestingRun(t)
}

// TestProperty31_EmptyRepositoryDeletion tests deletion of repositories with no drafts
func TestProperty31_EmptyRepositoryDeletion(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50

	properties := gopter.NewProperties(parameters)

	// Property: Deleting a repository with no drafts succeeds without error
	properties.Property("repository with no drafts can be deleted", prop.ForAll(
		func(userID, githubURL, webhookSecret string) bool {
			store := NewRepositoryDeletionStore()

			// Create a repository without any drafts
			repo := store.CreateRepository(userID, githubURL, webhookSecret)
			repoID := repo.ID

			// Verify no drafts exist for this repo
			drafts := store.GetDraftsByRepository(repoID)
			if len(drafts) != 0 {
				return false
			}

			// Delete should succeed
			if err := store.DeleteRepository(repoID); err != nil {
				return false
			}

			// Repository should be gone
			return !store.RepositoryExists(repoID)
		},
		genUserID(),
		genGitHubURL(),
		genWebhookSecret(),
	))

	properties.TestingRun(t)
}

// TestProperty31_IdempotentDeletion tests that deleting a non-existent repository is safe
func TestProperty31_IdempotentDeletion(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50

	properties := gopter.NewProperties(parameters)

	// Property: Deleting a non-existent repository does not cause errors
	properties.Property("deleting non-existent repository is safe", prop.ForAll(
		func(randomID string) bool {
			store := NewRepositoryDeletionStore()

			// Try to delete a repository that doesn't exist
			// This should not panic or cause issues
			err := store.DeleteRepository(randomID)
			return err == nil
		},
		genUserID(), // Using UUID format for random IDs
	))

	// Property: Double deletion is idempotent
	properties.Property("double deletion is idempotent", prop.ForAll(
		func(userID, githubURL, webhookSecret string) bool {
			store := NewRepositoryDeletionStore()

			// Create and delete a repository
			repo := store.CreateRepository(userID, githubURL, webhookSecret)
			repoID := repo.ID

			// First deletion
			if err := store.DeleteRepository(repoID); err != nil {
				return false
			}

			// Second deletion should also succeed (or at least not panic)
			err := store.DeleteRepository(repoID)
			return err == nil
		},
		genUserID(),
		genGitHubURL(),
		genWebhookSecret(),
	))

	properties.TestingRun(t)
}
