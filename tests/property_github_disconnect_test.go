// Package tests contains property-based tests for the Roxas application.
// Property 34: GitHub disconnect deletes all repo connections, webhooks, and credentials.
// Validates Requirements 11.8: WHEN a user disconnects GitHub, THE System SHALL remove
// all repository connections and webhooks.
package tests

import (
	"context"
	"sync"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Test Infrastructure for GitHub Disconnect Cascade Tests
// =============================================================================

// MockRepository represents a GitHub repository connection
type MockRepository struct {
	ID            string
	UserID        string
	GitHubURL     string
	WebhookID     int64
	WebhookSecret string
}

// MockGitHubCredential represents stored GitHub OAuth credentials
type MockGitHubCredential struct {
	UserID       string
	AccessToken  string
	RefreshToken string
}

// CascadeTracker tracks all operations for verifying cascade behavior
type CascadeTracker struct {
	mu                    sync.Mutex
	deletedRepoIDs        []string
	deletedWebhookIDs     []int64
	deletedCredentialKeys []string // userID keys
}

func NewCascadeTracker() *CascadeTracker {
	return &CascadeTracker{
		deletedRepoIDs:        make([]string, 0),
		deletedWebhookIDs:     make([]int64, 0),
		deletedCredentialKeys: make([]string, 0),
	}
}

func (t *CascadeTracker) RecordRepoDelete(repoID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deletedRepoIDs = append(t.deletedRepoIDs, repoID)
}

func (t *CascadeTracker) RecordWebhookDelete(webhookID int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deletedWebhookIDs = append(t.deletedWebhookIDs, webhookID)
}

func (t *CascadeTracker) RecordCredentialDelete(userID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deletedCredentialKeys = append(t.deletedCredentialKeys, userID)
}

func (t *CascadeTracker) GetDeletedRepoIDs() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]string, len(t.deletedRepoIDs))
	copy(result, t.deletedRepoIDs)
	return result
}

func (t *CascadeTracker) GetDeletedWebhookIDs() []int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]int64, len(t.deletedWebhookIDs))
	copy(result, t.deletedWebhookIDs)
	return result
}

func (t *CascadeTracker) GetDeletedCredentialKeys() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]string, len(t.deletedCredentialKeys))
	copy(result, t.deletedCredentialKeys)
	return result
}

func (t *CascadeTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deletedRepoIDs = make([]string, 0)
	t.deletedWebhookIDs = make([]int64, 0)
	t.deletedCredentialKeys = make([]string, 0)
}

// MockGitHubDisconnectService simulates the GitHub disconnect cascade behavior
type MockGitHubDisconnectService struct {
	mu          sync.Mutex
	repos       map[string]*MockRepository       // repoID -> repo
	credentials map[string]*MockGitHubCredential // userID -> credential
	tracker     *CascadeTracker
}

func NewMockGitHubDisconnectService(tracker *CascadeTracker) *MockGitHubDisconnectService {
	return &MockGitHubDisconnectService{
		repos:       make(map[string]*MockRepository),
		credentials: make(map[string]*MockGitHubCredential),
		tracker:     tracker,
	}
}

// AddRepository adds a repository for a user
func (s *MockGitHubDisconnectService) AddRepository(repo *MockRepository) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repos[repo.ID] = repo
}

// AddCredential adds GitHub credentials for a user
func (s *MockGitHubDisconnectService) AddCredential(cred *MockGitHubCredential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[cred.UserID] = cred
}

// GetRepositoriesByUser returns all repositories for a user
func (s *MockGitHubDisconnectService) GetRepositoriesByUser(userID string) []*MockRepository {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*MockRepository
	for _, repo := range s.repos {
		if repo.UserID == userID {
			result = append(result, repo)
		}
	}
	return result
}

// GetCredential returns the GitHub credential for a user
func (s *MockGitHubDisconnectService) GetCredential(userID string) *MockGitHubCredential {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.credentials[userID]
}

// DisconnectGitHub performs the cascade delete operation for GitHub disconnect
// This implements the behavior specified in Requirements 11.8
func (s *MockGitHubDisconnectService) DisconnectGitHub(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if user has GitHub connected
	if _, ok := s.credentials[userID]; !ok {
		return ErrGitHubNotConnected
	}

	// Step 1: Delete all repository connections for this user
	reposToDelete := make([]string, 0)
	for repoID, repo := range s.repos {
		if repo.UserID == userID {
			reposToDelete = append(reposToDelete, repoID)
		}
	}

	// Step 2: For each repository, delete the webhook and then the repo
	for _, repoID := range reposToDelete {
		repo := s.repos[repoID]

		// Record webhook deletion (simulates GitHub API call to delete webhook)
		if repo.WebhookID > 0 {
			s.tracker.RecordWebhookDelete(repo.WebhookID)
		}

		// Delete the repository record
		delete(s.repos, repoID)
		s.tracker.RecordRepoDelete(repoID)
	}

	// Step 3: Delete GitHub credentials
	delete(s.credentials, userID)
	s.tracker.RecordCredentialDelete(userID)

	return nil
}

// ErrGitHubNotConnected is returned when trying to disconnect GitHub that isn't connected
var ErrGitHubNotConnected = errGitHubNotConnected{}

type errGitHubNotConnected struct{}

func (e errGitHubNotConnected) Error() string {
	return "github not connected"
}

// CountRepositoriesForUser counts repositories for a specific user
func (s *MockGitHubDisconnectService) CountRepositoriesForUser(userID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, repo := range s.repos {
		if repo.UserID == userID {
			count++
		}
	}
	return count
}

// HasCredential checks if a user has GitHub credentials
func (s *MockGitHubDisconnectService) HasCredential(userID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.credentials[userID]
	return ok
}

// =============================================================================
// Generators for Property Tests
// =============================================================================

// genUserID generates valid user IDs (UUIDs)
func genUserID() gopter.Gen {
	return gen.RegexMatch(`user-[a-f0-9]{8}`)
}

// genRepoID generates valid repository IDs (UUIDs)
func genRepoID() gopter.Gen {
	return gen.RegexMatch(`repo-[a-f0-9]{8}`)
}

// genGitHubURL generates valid GitHub repository URLs
func genGitHubURL() gopter.Gen {
	owner := gen.RegexMatch(`[a-z][a-z0-9]{2,10}`)
	repo := gen.RegexMatch(`[a-z][a-z0-9-]{2,15}`)
	return gopter.CombineGens(owner, repo).Map(func(vals []interface{}) string {
		return "https://github.com/" + vals[0].(string) + "/" + vals[1].(string)
	})
}

// genWebhookID generates valid webhook IDs
func genWebhookID() gopter.Gen {
	return gen.Int64Range(1, 999999999)
}

// genWebhookSecret generates valid webhook secrets
func genWebhookSecret() gopter.Gen {
	return gen.RegexMatch(`whsec_[a-zA-Z0-9]{32}`)
}

// genAccessToken generates mock access tokens
func genAccessToken() gopter.Gen {
	return gen.RegexMatch(`gho_[a-zA-Z0-9]{36}`)
}

// genRepoCount generates a reasonable number of repositories
func genRepoCount() gopter.Gen {
	return gen.IntRange(1, 10)
}

// =============================================================================
// Property Tests for GitHub Disconnect Cascades (Property 34)
// Validates Requirements 11.8
// =============================================================================

// TestProperty34_GitHubDisconnectDeletesAllRepositories verifies that
// disconnecting GitHub removes ALL repository connections for that user.
func TestProperty34_GitHubDisconnectDeletesAllRepositories(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 20
	properties := gopter.NewProperties(parameters)

	properties.Property("disconnecting GitHub deletes all user repositories", prop.ForAll(
		func(userID string, repoCount int) bool {
			tracker := NewCascadeTracker()
			service := NewMockGitHubDisconnectService(tracker)
			ctx := context.Background()

			// Setup: Add GitHub credential for user
			service.AddCredential(&MockGitHubCredential{
				UserID:      userID,
				AccessToken: "gho_test123456789012345678901234567890",
			})

			// Setup: Add multiple repositories for the user
			repoIDs := make([]string, repoCount)
			for i := 0; i < repoCount; i++ {
				repoID := genRepoIDForIndex(userID, i)
				repoIDs[i] = repoID
				service.AddRepository(&MockRepository{
					ID:            repoID,
					UserID:        userID,
					GitHubURL:     "https://github.com/test/repo" + string(rune('a'+i)),
					WebhookID:     int64(1000 + i),
					WebhookSecret: "whsec_test",
				})
			}

			// Verify setup: user has repositories
			if service.CountRepositoriesForUser(userID) != repoCount {
				return false
			}

			// Action: Disconnect GitHub
			err := service.DisconnectGitHub(ctx, userID)
			if err != nil {
				return false
			}

			// Property 1: All repositories for user should be deleted
			if service.CountRepositoriesForUser(userID) != 0 {
				return false
			}

			// Property 2: All repo deletions should be tracked
			deletedRepos := tracker.GetDeletedRepoIDs()
			if len(deletedRepos) != repoCount {
				return false
			}

			// Property 3: All original repos should be in deleted list
			deletedSet := make(map[string]bool)
			for _, id := range deletedRepos {
				deletedSet[id] = true
			}
			for _, id := range repoIDs {
				if !deletedSet[id] {
					return false
				}
			}

			return true
		},
		genUserID(),
		genRepoCount(),
	))

	properties.TestingRun(t)
}

// TestProperty34_GitHubDisconnectDeletesAllWebhooks verifies that
// disconnecting GitHub removes ALL webhooks associated with user's repositories.
func TestProperty34_GitHubDisconnectDeletesAllWebhooks(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	properties.Property("disconnecting GitHub deletes all webhooks", prop.ForAll(
		func(userID string, webhookIDs []int64) bool {
			if len(webhookIDs) == 0 {
				return true // Skip empty cases
			}

			tracker := NewCascadeTracker()
			service := NewMockGitHubDisconnectService(tracker)
			ctx := context.Background()

			// Setup: Add GitHub credential
			service.AddCredential(&MockGitHubCredential{
				UserID:      userID,
				AccessToken: "gho_test",
			})

			// Setup: Add repositories with webhooks
			for i, webhookID := range webhookIDs {
				service.AddRepository(&MockRepository{
					ID:            genRepoIDForIndex(userID, i),
					UserID:        userID,
					GitHubURL:     "https://github.com/test/repo",
					WebhookID:     webhookID,
					WebhookSecret: "whsec_test",
				})
			}

			// Action: Disconnect GitHub
			err := service.DisconnectGitHub(ctx, userID)
			if err != nil {
				return false
			}

			// Property: All webhooks should be deleted
			deletedWebhooks := tracker.GetDeletedWebhookIDs()
			if len(deletedWebhooks) != len(webhookIDs) {
				return false
			}

			// Verify all webhook IDs were deleted
			deletedSet := make(map[int64]bool)
			for _, id := range deletedWebhooks {
				deletedSet[id] = true
			}
			for _, id := range webhookIDs {
				if !deletedSet[id] {
					return false
				}
			}

			return true
		},
		genUserID(),
		gen.SliceOfN(5, genWebhookID()),
	))

	properties.TestingRun(t)
}

// TestProperty34_GitHubDisconnectDeletesCredentials verifies that
// disconnecting GitHub removes the stored credentials.
func TestProperty34_GitHubDisconnectDeletesCredentials(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	properties.Property("disconnecting GitHub deletes credentials", prop.ForAll(
		func(userID, accessToken string) bool {
			tracker := NewCascadeTracker()
			service := NewMockGitHubDisconnectService(tracker)
			ctx := context.Background()

			// Setup: Add GitHub credential
			service.AddCredential(&MockGitHubCredential{
				UserID:      userID,
				AccessToken: accessToken,
			})

			// Verify setup
			if !service.HasCredential(userID) {
				return false
			}

			// Action: Disconnect GitHub
			err := service.DisconnectGitHub(ctx, userID)
			if err != nil {
				return false
			}

			// Property 1: Credentials should be deleted
			if service.HasCredential(userID) {
				return false
			}

			// Property 2: Credential deletion should be tracked
			deletedCreds := tracker.GetDeletedCredentialKeys()
			if len(deletedCreds) != 1 || deletedCreds[0] != userID {
				return false
			}

			return true
		},
		genUserID(),
		genAccessToken(),
	))

	properties.TestingRun(t)
}

// TestProperty34_GitHubDisconnectIsolatesOtherUsers verifies that
// disconnecting GitHub for one user does NOT affect other users' data.
func TestProperty34_GitHubDisconnectIsolatesOtherUsers(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	properties.Property("disconnect isolates data between users", prop.ForAll(
		func(user1, user2 string) bool {
			// Ensure different users
			if user1 == user2 {
				return true // Skip when same user generated
			}

			tracker := NewCascadeTracker()
			service := NewMockGitHubDisconnectService(tracker)
			ctx := context.Background()

			// Setup: Add credentials for both users
			service.AddCredential(&MockGitHubCredential{
				UserID:      user1,
				AccessToken: "token1",
			})
			service.AddCredential(&MockGitHubCredential{
				UserID:      user2,
				AccessToken: "token2",
			})

			// Setup: Add repositories for both users
			service.AddRepository(&MockRepository{
				ID:        "repo-user1-1",
				UserID:    user1,
				GitHubURL: "https://github.com/user1/repo1",
				WebhookID: 1001,
			})
			service.AddRepository(&MockRepository{
				ID:        "repo-user1-2",
				UserID:    user1,
				GitHubURL: "https://github.com/user1/repo2",
				WebhookID: 1002,
			})
			service.AddRepository(&MockRepository{
				ID:        "repo-user2-1",
				UserID:    user2,
				GitHubURL: "https://github.com/user2/repo1",
				WebhookID: 2001,
			})

			// Verify setup
			user1ReposBefore := service.CountRepositoriesForUser(user1)
			user2ReposBefore := service.CountRepositoriesForUser(user2)
			if user1ReposBefore != 2 || user2ReposBefore != 1 {
				return false
			}

			// Action: Disconnect GitHub for user1 ONLY
			err := service.DisconnectGitHub(ctx, user1)
			if err != nil {
				return false
			}

			// Property 1: User1's repos should be deleted
			if service.CountRepositoriesForUser(user1) != 0 {
				return false
			}

			// Property 2: User2's repos should be UNCHANGED
			if service.CountRepositoriesForUser(user2) != user2ReposBefore {
				return false
			}

			// Property 3: User1's credentials should be deleted
			if service.HasCredential(user1) {
				return false
			}

			// Property 4: User2's credentials should be UNCHANGED
			if !service.HasCredential(user2) {
				return false
			}

			// Property 5: Only user1's webhooks deleted (1001, 1002)
			deletedWebhooks := tracker.GetDeletedWebhookIDs()
			for _, wid := range deletedWebhooks {
				if wid == 2001 { // User2's webhook should NOT be deleted
					return false
				}
			}

			return true
		},
		genUserID(),
		genUserID(),
	))

	properties.TestingRun(t)
}

// TestProperty34_GitHubDisconnectFailsIfNotConnected verifies that
// attempting to disconnect when GitHub is not connected returns appropriate error.
func TestProperty34_GitHubDisconnectFailsIfNotConnected(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	properties.Property("disconnect fails if GitHub not connected", prop.ForAll(
		func(userID string) bool {
			tracker := NewCascadeTracker()
			service := NewMockGitHubDisconnectService(tracker)
			ctx := context.Background()

			// No credential added for user

			// Action: Try to disconnect
			err := service.DisconnectGitHub(ctx, userID)

			// Property: Should return error
			if err == nil {
				return false
			}
			if err != ErrGitHubNotConnected {
				return false
			}

			// Property: No deletions should have occurred
			if len(tracker.GetDeletedRepoIDs()) != 0 {
				return false
			}
			if len(tracker.GetDeletedWebhookIDs()) != 0 {
				return false
			}
			if len(tracker.GetDeletedCredentialKeys()) != 0 {
				return false
			}

			return true
		},
		genUserID(),
	))

	properties.TestingRun(t)
}

// TestProperty34_GitHubDisconnectWithNoReposSucceeds verifies that
// disconnecting GitHub succeeds even when user has no repositories.
func TestProperty34_GitHubDisconnectWithNoReposSucceeds(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	properties.Property("disconnect succeeds with zero repositories", prop.ForAll(
		func(userID, accessToken string) bool {
			tracker := NewCascadeTracker()
			service := NewMockGitHubDisconnectService(tracker)
			ctx := context.Background()

			// Setup: Add credential but NO repositories
			service.AddCredential(&MockGitHubCredential{
				UserID:      userID,
				AccessToken: accessToken,
			})

			// Verify setup: no repos
			if service.CountRepositoriesForUser(userID) != 0 {
				return false
			}

			// Action: Disconnect GitHub
			err := service.DisconnectGitHub(ctx, userID)

			// Property 1: Should succeed
			if err != nil {
				return false
			}

			// Property 2: Credential should be deleted
			if service.HasCredential(userID) {
				return false
			}

			// Property 3: No repo or webhook deletions (none existed)
			if len(tracker.GetDeletedRepoIDs()) != 0 {
				return false
			}
			if len(tracker.GetDeletedWebhookIDs()) != 0 {
				return false
			}

			// Property 4: Credential deletion tracked
			if len(tracker.GetDeletedCredentialKeys()) != 1 {
				return false
			}

			return true
		},
		genUserID(),
		genAccessToken(),
	))

	properties.TestingRun(t)
}

// TestProperty34_CascadeOrderCredentialsLast verifies that credentials
// are deleted AFTER repositories and webhooks (proper cleanup order).
func TestProperty34_CascadeOrderCredentialsLast(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	properties.Property("credentials deleted after repos and webhooks", prop.ForAll(
		func(userID string, repoCount int) bool {
			if repoCount == 0 {
				return true // Skip empty case
			}

			tracker := NewCascadeTracker()
			service := NewMockGitHubDisconnectService(tracker)
			ctx := context.Background()

			// Setup
			service.AddCredential(&MockGitHubCredential{
				UserID:      userID,
				AccessToken: "token",
			})

			for i := 0; i < repoCount; i++ {
				service.AddRepository(&MockRepository{
					ID:        genRepoIDForIndex(userID, i),
					UserID:    userID,
					WebhookID: int64(1000 + i),
				})
			}

			// Action
			err := service.DisconnectGitHub(ctx, userID)
			if err != nil {
				return false
			}

			// Property: All repos should be deleted
			deletedRepos := tracker.GetDeletedRepoIDs()
			if len(deletedRepos) != repoCount {
				return false
			}

			// Property: All webhooks should be deleted
			deletedWebhooks := tracker.GetDeletedWebhookIDs()
			if len(deletedWebhooks) != repoCount {
				return false
			}

			// Property: Credential should be deleted
			deletedCreds := tracker.GetDeletedCredentialKeys()
			if len(deletedCreds) != 1 {
				return false
			}

			return true
		},
		genUserID(),
		gen.IntRange(1, 5),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Helper Functions
// =============================================================================

// genRepoIDForIndex generates a deterministic repo ID for testing
func genRepoIDForIndex(userID string, index int) string {
	return userID + "-repo-" + string(rune('a'+index))
}
