package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Property Test: Multi-Tenant Draft Creation
// Property 17: N users tracking repo = N separate drafts with personalized AI content
// Validates Requirements 5.7, 5.9, 14.1, 14.2
// =============================================================================

// MockMultiTenantDraftStore tracks drafts per user for multi-tenant testing
type MockMultiTenantDraftStore struct {
	mu     sync.Mutex
	drafts map[string][]*WebhookDraft // userID -> drafts
	nextID int
}

func NewMockMultiTenantDraftStore() *MockMultiTenantDraftStore {
	return &MockMultiTenantDraftStore{
		drafts: make(map[string][]*WebhookDraft),
		nextID: 1,
	}
}

func (m *MockMultiTenantDraftStore) CreateDraftFromPush(ctx context.Context, userID, repoID, ref, beforeSHA, afterSHA string, commitSHAs []string) (*WebhookDraft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	draft := &WebhookDraft{
		ID:           fmt.Sprintf("draft-%d", m.nextID),
		UserID:       userID,
		RepositoryID: repoID,
		Ref:          ref,
		BeforeSHA:    beforeSHA,
		AfterSHA:     afterSHA,
		CommitSHAs:   commitSHAs,
		Status:       "draft",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	m.nextID++
	m.drafts[userID] = append(m.drafts[userID], draft)
	return draft, nil
}

func (m *MockMultiTenantDraftStore) GetDraftByPushSignature(ctx context.Context, repoID, beforeSHA, afterSHA string) (*WebhookDraft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, userDrafts := range m.drafts {
		for _, d := range userDrafts {
			if d.RepositoryID == repoID && d.BeforeSHA == beforeSHA && d.AfterSHA == afterSHA {
				return d, nil
			}
		}
	}
	return nil, nil
}

func (m *MockMultiTenantDraftStore) GetAllDrafts() []*WebhookDraft {
	m.mu.Lock()
	defer m.mu.Unlock()

	var all []*WebhookDraft
	for _, userDrafts := range m.drafts {
		all = append(all, userDrafts...)
	}
	return all
}

func (m *MockMultiTenantDraftStore) GetDraftsByUser(userID string) []*WebhookDraft {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.drafts[userID]
}

func (m *MockMultiTenantDraftStore) GetDraftCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for _, userDrafts := range m.drafts {
		count += len(userDrafts)
	}
	return count
}

// MockPersonalizedAIGenerator generates personalized content based on user context
type MockPersonalizedAIGenerator struct {
	mu                  sync.Mutex
	generatedContent    map[string]string // draftID -> content
	generationCount     int
	userGenerationCount map[string]int
}

func NewMockPersonalizedAIGenerator() *MockPersonalizedAIGenerator {
	return &MockPersonalizedAIGenerator{
		generatedContent:    make(map[string]string),
		userGenerationCount: make(map[string]int),
	}
}

func (m *MockPersonalizedAIGenerator) TriggerGeneration(ctx context.Context, draftID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.generationCount++
	// Generate personalized content using random bytes to ensure uniqueness
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	content := fmt.Sprintf("Personalized content #%d - %s", m.generationCount, hex.EncodeToString(randBytes))
	m.generatedContent[draftID] = content

	return nil
}

func (m *MockPersonalizedAIGenerator) GetGeneratedContent(draftID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generatedContent[draftID]
}

func (m *MockPersonalizedAIGenerator) GetGenerationCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generationCount
}

func (m *MockPersonalizedAIGenerator) GetAllContent() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make(map[string]string)
	for k, v := range m.generatedContent {
		result[k] = v
	}
	return result
}

// MockMultiTenantRepoStore stores repositories for multiple users tracking the same GitHub URL
type MockMultiTenantRepoStore struct {
	mu    sync.Mutex
	repos map[string]*Repository // repoID -> Repository
}

func NewMockMultiTenantRepoStore() *MockMultiTenantRepoStore {
	return &MockMultiTenantRepoStore{
		repos: make(map[string]*Repository),
	}
}

func (m *MockMultiTenantRepoStore) GetRepositoryByID(ctx context.Context, repoID string) (*Repository, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.repos[repoID], nil
}

func (m *MockMultiTenantRepoStore) AddRepository(repo *Repository) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.repos[repo.ID] = repo
}

func (m *MockMultiTenantRepoStore) GetAllRepos() []*Repository {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []*Repository
	for _, r := range m.repos {
		result = append(result, r)
	}
	return result
}

// MockMultiTenantIdempotencyStore tracks delivery processing per repo
type MockMultiTenantIdempotencyStore struct {
	mu           sync.Mutex
	processedIDs map[string]bool // deliveryID -> processed
}

func NewMockMultiTenantIdempotencyStore() *MockMultiTenantIdempotencyStore {
	return &MockMultiTenantIdempotencyStore{
		processedIDs: make(map[string]bool),
	}
}

func (m *MockMultiTenantIdempotencyStore) CheckDeliveryProcessed(ctx context.Context, deliveryID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.processedIDs[deliveryID], nil
}

func (m *MockMultiTenantIdempotencyStore) MarkDeliveryProcessed(ctx context.Context, deliveryID, repoID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.processedIDs[deliveryID] = true
	return nil
}

// =============================================================================
// Property Test: N users tracking same repo = N separate drafts
// =============================================================================

func TestProperty_MultiTenantDraftCreation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 20

	properties := gopter.NewProperties(parameters)

	// Property 17a: N users tracking the same repo creates N separate drafts
	properties.Property("N users tracking same repo creates N separate drafts", prop.ForAll(
		func(numUsers int, githubRepoURL string) bool {
			repoStore := NewMockMultiTenantRepoStore()
			draftStore := NewMockMultiTenantDraftStore()
			aiGenerator := NewMockPersonalizedAIGenerator()

			// Create N users, each with their own repository record for the same GitHub URL
			userRepos := make([]*Repository, numUsers)
			handlers := make([]*DraftCreatingWebhookHandler, numUsers)
			idempotencyStores := make([]*MockMultiTenantIdempotencyStore, numUsers)

			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				repoID := fmt.Sprintf("repo-%d", i)

				// Generate unique webhook secret per user
				secretBytes := make([]byte, 32)
				rand.Read(secretBytes)
				webhookSecret := hex.EncodeToString(secretBytes)

				repo := &Repository{
					ID:            repoID,
					UserID:        userID,
					GitHubURL:     githubRepoURL,
					WebhookSecret: webhookSecret,
					CreatedAt:     time.Now(),
				}
				repoStore.AddRepository(repo)
				userRepos[i] = repo

				// Each user has their own idempotency store to simulate separate webhook endpoints
				idempotencyStores[i] = NewMockMultiTenantIdempotencyStore()

				// Create handler for this user's webhook
				handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempotencyStores[i])
				handler = handler.WithAIGenerator(aiGenerator)
				handlers[i] = handler
			}

			// Simulate a push to the GitHub repo
			// In multi-tenant mode, GitHub sends a webhook to each user's endpoint
			beforeSHA := "0000000000000000000000000000000000000000"
			afterSHA := "abc123def456789012345678901234567890abcd"
			commits := []map[string]interface{}{
				{
					"id":      "abc123def456",
					"message": "feat: add multi-tenant support",
					"author":  map[string]interface{}{"name": "Developer", "email": "dev@example.com"},
				},
			}
			payload := createPushPayloadWithSHAs(beforeSHA, afterSHA, commits)

			// Send webhook to each user's handler
			for i := 0; i < numUsers; i++ {
				signature := generateGitHubSignature(payload, userRepos[i].WebhookSecret)
				deliveryID := fmt.Sprintf("delivery-%d-%s", i, hex.EncodeToString(make([]byte, 8)))

				req := createDraftWebhookRequest(t, userRepos[i].ID, payload, signature, deliveryID)
				req.Header.Set("X-GitHub-Event", "push")

				rr := httptest.NewRecorder()
				handlers[i].ServeHTTP(rr, req)

				if rr.Code != http.StatusOK {
					t.Logf("User %d webhook failed with status %d: %s", i, rr.Code, rr.Body.String())
					return false
				}
			}

			// Verify: N users = N drafts
			totalDrafts := draftStore.GetDraftCount()
			if totalDrafts != numUsers {
				t.Logf("Expected %d drafts, got %d", numUsers, totalDrafts)
				return false
			}

			// Verify: Each user has exactly one draft
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				userDrafts := draftStore.GetDraftsByUser(userID)
				if len(userDrafts) != 1 {
					t.Logf("User %s has %d drafts, expected 1", userID, len(userDrafts))
					return false
				}
			}

			return true
		},
		gen.IntRange(2, 20), // 2-20 users
		gen.AlphaString().Map(func(s string) string {
			if len(s) < 3 {
				s = "testrepo"
			}
			return "https://github.com/shared-org/" + s
		}),
	))

	properties.TestingRun(t)
}

// TestProperty_MultiTenantDraftsHaveUniqueIDs verifies each draft has a unique ID
func TestProperty_MultiTenantDraftsHaveUniqueIDs(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 30

	properties := gopter.NewProperties(parameters)

	properties.Property("each user's draft has a unique ID", prop.ForAll(
		func(numUsers int) bool {
			repoStore := NewMockMultiTenantRepoStore()
			draftStore := NewMockMultiTenantDraftStore()
			aiGenerator := NewMockPersonalizedAIGenerator()
			githubRepoURL := "https://github.com/shared/project"

			// Setup users and repos
			var repos []*Repository
			var handlers []*DraftCreatingWebhookHandler
			var idempotencyStores []*MockMultiTenantIdempotencyStore

			for i := 0; i < numUsers; i++ {
				secretBytes := make([]byte, 32)
				rand.Read(secretBytes)

				repo := &Repository{
					ID:            fmt.Sprintf("repo-%d", i),
					UserID:        fmt.Sprintf("user-%d", i),
					GitHubURL:     githubRepoURL,
					WebhookSecret: hex.EncodeToString(secretBytes),
					CreatedAt:     time.Now(),
				}
				repoStore.AddRepository(repo)
				repos = append(repos, repo)

				idempStore := NewMockMultiTenantIdempotencyStore()
				idempotencyStores = append(idempotencyStores, idempStore)

				handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempStore).
					WithAIGenerator(aiGenerator)
				handlers = append(handlers, handler)
			}

			// Simulate push
			payload := createPushPayloadWithSHAs("before", "after", []map[string]interface{}{
				{"id": "commit1", "message": "test", "author": map[string]interface{}{"name": "Dev"}},
			})

			for i := 0; i < numUsers; i++ {
				sig := generateGitHubSignature(payload, repos[i].WebhookSecret)
				req := createDraftWebhookRequest(t, repos[i].ID, payload, sig, fmt.Sprintf("delivery-%d", i))
				req.Header.Set("X-GitHub-Event", "push")

				rr := httptest.NewRecorder()
				handlers[i].ServeHTTP(rr, req)

				if rr.Code != http.StatusOK {
					return false
				}
			}

			// Verify all draft IDs are unique
			allDrafts := draftStore.GetAllDrafts()
			draftIDs := make(map[string]bool)
			for _, draft := range allDrafts {
				if draftIDs[draft.ID] {
					t.Logf("Duplicate draft ID found: %s", draft.ID)
					return false
				}
				draftIDs[draft.ID] = true
			}

			return len(draftIDs) == numUsers
		},
		gen.IntRange(2, 30),
	))

	properties.TestingRun(t)
}

// TestProperty_MultiTenantAIGenerationTriggeredPerUser verifies AI generation is triggered for each user's draft
func TestProperty_MultiTenantAIGenerationTriggeredPerUser(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 15

	properties := gopter.NewProperties(parameters)

	properties.Property("AI generation triggered N times for N users", prop.ForAll(
		func(numUsers int) bool {
			repoStore := NewMockMultiTenantRepoStore()
			draftStore := NewMockMultiTenantDraftStore()
			aiGenerator := NewMockPersonalizedAIGenerator()
			githubRepoURL := "https://github.com/shared/ai-project"

			// Setup
			var repos []*Repository
			var handlers []*DraftCreatingWebhookHandler
			var idempotencyStores []*MockMultiTenantIdempotencyStore

			for i := 0; i < numUsers; i++ {
				secretBytes := make([]byte, 32)
				rand.Read(secretBytes)

				repo := &Repository{
					ID:            fmt.Sprintf("repo-%d", i),
					UserID:        fmt.Sprintf("user-%d", i),
					GitHubURL:     githubRepoURL,
					WebhookSecret: hex.EncodeToString(secretBytes),
					CreatedAt:     time.Now(),
				}
				repoStore.AddRepository(repo)
				repos = append(repos, repo)

				idempStore := NewMockMultiTenantIdempotencyStore()
				idempotencyStores = append(idempotencyStores, idempStore)

				handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempStore).
					WithAIGenerator(aiGenerator)
				handlers = append(handlers, handler)
			}

			// Simulate push
			payload := createPushPayloadWithSHAs("before", "after", []map[string]interface{}{
				{"id": "commit1", "message": "feat: amazing feature", "author": map[string]interface{}{"name": "Dev"}},
			})

			for i := 0; i < numUsers; i++ {
				sig := generateGitHubSignature(payload, repos[i].WebhookSecret)
				req := createDraftWebhookRequest(t, repos[i].ID, payload, sig, fmt.Sprintf("delivery-%d", i))
				req.Header.Set("X-GitHub-Event", "push")

				rr := httptest.NewRecorder()
				handlers[i].ServeHTTP(rr, req)
			}

			// Verify AI generation was triggered N times
			generationCount := aiGenerator.GetGenerationCount()
			if generationCount != numUsers {
				t.Logf("Expected %d AI generations, got %d", numUsers, generationCount)
				return false
			}

			return true
		},
		gen.IntRange(2, 15),
	))

	properties.TestingRun(t)
}

// TestProperty_MultiTenantPersonalizedContent verifies each user gets unique personalized content
func TestProperty_MultiTenantPersonalizedContent(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	parameters.MaxSize = 10

	properties := gopter.NewProperties(parameters)

	properties.Property("each user gets unique personalized AI content", prop.ForAll(
		func(numUsers int) bool {
			repoStore := NewMockMultiTenantRepoStore()
			draftStore := NewMockMultiTenantDraftStore()
			aiGenerator := NewMockPersonalizedAIGenerator()
			githubRepoURL := "https://github.com/shared/personalized"

			// Setup
			var repos []*Repository
			var handlers []*DraftCreatingWebhookHandler
			var idempotencyStores []*MockMultiTenantIdempotencyStore

			for i := 0; i < numUsers; i++ {
				secretBytes := make([]byte, 32)
				rand.Read(secretBytes)

				repo := &Repository{
					ID:            fmt.Sprintf("repo-%d", i),
					UserID:        fmt.Sprintf("user-%d", i),
					GitHubURL:     githubRepoURL,
					WebhookSecret: hex.EncodeToString(secretBytes),
					CreatedAt:     time.Now(),
				}
				repoStore.AddRepository(repo)
				repos = append(repos, repo)

				idempStore := NewMockMultiTenantIdempotencyStore()
				idempotencyStores = append(idempotencyStores, idempStore)

				handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempStore).
					WithAIGenerator(aiGenerator)
				handlers = append(handlers, handler)
			}

			// Simulate push
			payload := createPushPayloadWithSHAs("before", "after", []map[string]interface{}{
				{"id": "commit1", "message": "personalized content test", "author": map[string]interface{}{"name": "Dev"}},
			})

			for i := 0; i < numUsers; i++ {
				sig := generateGitHubSignature(payload, repos[i].WebhookSecret)
				req := createDraftWebhookRequest(t, repos[i].ID, payload, sig, fmt.Sprintf("delivery-%d", i))
				req.Header.Set("X-GitHub-Event", "push")

				rr := httptest.NewRecorder()
				handlers[i].ServeHTTP(rr, req)
			}

			// Verify all generated content is unique
			allContent := aiGenerator.GetAllContent()
			contentSet := make(map[string]string) // content -> draftID

			for draftID, content := range allContent {
				if existingDraftID, exists := contentSet[content]; exists {
					t.Logf("Duplicate content found for drafts %s and %s", existingDraftID, draftID)
					return false
				}
				contentSet[content] = draftID
			}

			// Should have N unique content entries
			if len(contentSet) != numUsers {
				t.Logf("Expected %d unique content entries, got %d", numUsers, len(contentSet))
				return false
			}

			return true
		},
		gen.IntRange(2, 10),
	))

	properties.TestingRun(t)
}

// TestProperty_MultiTenantDraftIsolation verifies drafts are isolated between users
func TestProperty_MultiTenantDraftIsolation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 20

	properties := gopter.NewProperties(parameters)

	properties.Property("drafts are isolated between users - user A cannot see user B's drafts", prop.ForAll(
		func(numUsers int) bool {
			repoStore := NewMockMultiTenantRepoStore()
			draftStore := NewMockMultiTenantDraftStore()
			aiGenerator := NewMockPersonalizedAIGenerator()
			githubRepoURL := "https://github.com/shared/isolation-test"

			// Setup
			var repos []*Repository
			var handlers []*DraftCreatingWebhookHandler
			var idempotencyStores []*MockMultiTenantIdempotencyStore

			for i := 0; i < numUsers; i++ {
				secretBytes := make([]byte, 32)
				rand.Read(secretBytes)

				repo := &Repository{
					ID:            fmt.Sprintf("repo-%d", i),
					UserID:        fmt.Sprintf("user-%d", i),
					GitHubURL:     githubRepoURL,
					WebhookSecret: hex.EncodeToString(secretBytes),
					CreatedAt:     time.Now(),
				}
				repoStore.AddRepository(repo)
				repos = append(repos, repo)

				idempStore := NewMockMultiTenantIdempotencyStore()
				idempotencyStores = append(idempotencyStores, idempStore)

				handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempStore).
					WithAIGenerator(aiGenerator)
				handlers = append(handlers, handler)
			}

			// Simulate push
			payload := createPushPayloadWithSHAs("before", "after", []map[string]interface{}{
				{"id": "commit1", "message": "isolation test", "author": map[string]interface{}{"name": "Dev"}},
			})

			for i := 0; i < numUsers; i++ {
				sig := generateGitHubSignature(payload, repos[i].WebhookSecret)
				req := createDraftWebhookRequest(t, repos[i].ID, payload, sig, fmt.Sprintf("delivery-%d", i))
				req.Header.Set("X-GitHub-Event", "push")

				rr := httptest.NewRecorder()
				handlers[i].ServeHTTP(rr, req)
			}

			// Verify each user's drafts only belong to them
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				repoID := fmt.Sprintf("repo-%d", i)
				userDrafts := draftStore.GetDraftsByUser(userID)

				for _, draft := range userDrafts {
					// Draft's UserID must match
					if draft.UserID != userID {
						t.Logf("Draft %s has wrong UserID: expected %s, got %s", draft.ID, userID, draft.UserID)
						return false
					}
					// Draft's RepositoryID must match this user's repo
					if draft.RepositoryID != repoID {
						t.Logf("Draft %s has wrong RepositoryID: expected %s, got %s", draft.ID, repoID, draft.RepositoryID)
						return false
					}
				}
			}

			return true
		},
		gen.IntRange(2, 20),
	))

	properties.TestingRun(t)
}

// TestProperty_MultiTenantWebhookSecretIsolation verifies webhook secrets are per-user
func TestProperty_MultiTenantWebhookSecretIsolation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	parameters.MaxSize = 10

	properties := gopter.NewProperties(parameters)

	properties.Property("one user's webhook secret cannot create drafts for another user", prop.ForAll(
		func(numUsers int) bool {
			repoStore := NewMockMultiTenantRepoStore()
			draftStore := NewMockMultiTenantDraftStore()
			aiGenerator := NewMockPersonalizedAIGenerator()
			githubRepoURL := "https://github.com/shared/secret-test"

			// Setup
			var repos []*Repository
			var handlers []*DraftCreatingWebhookHandler
			var idempotencyStores []*MockMultiTenantIdempotencyStore

			for i := 0; i < numUsers; i++ {
				secretBytes := make([]byte, 32)
				rand.Read(secretBytes)

				repo := &Repository{
					ID:            fmt.Sprintf("repo-%d", i),
					UserID:        fmt.Sprintf("user-%d", i),
					GitHubURL:     githubRepoURL,
					WebhookSecret: hex.EncodeToString(secretBytes),
					CreatedAt:     time.Now(),
				}
				repoStore.AddRepository(repo)
				repos = append(repos, repo)

				idempStore := NewMockMultiTenantIdempotencyStore()
				idempotencyStores = append(idempotencyStores, idempStore)

				handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempStore).
					WithAIGenerator(aiGenerator)
				handlers = append(handlers, handler)
			}

			payload := createPushPayloadWithSHAs("before", "after", []map[string]interface{}{
				{"id": "commit1", "message": "secret test", "author": map[string]interface{}{"name": "Dev"}},
			})

			// For each user, try to use another user's secret (should fail)
			for i := 0; i < numUsers; i++ {
				for j := 0; j < numUsers; j++ {
					if i == j {
						continue // Skip same user
					}

					// Use user j's secret to sign webhook for user i's repo
					wrongSig := generateGitHubSignature(payload, repos[j].WebhookSecret)
					req := createDraftWebhookRequest(t, repos[i].ID, payload, wrongSig, fmt.Sprintf("cross-delivery-%d-%d", i, j))
					req.Header.Set("X-GitHub-Event", "push")

					rr := httptest.NewRecorder()
					handlers[i].ServeHTTP(rr, req)

					// Should be rejected with 401
					if rr.Code == http.StatusOK {
						t.Logf("User %d's secret was accepted for user %d's repo", j, i)
						return false
					}
					if rr.Code != http.StatusUnauthorized {
						t.Logf("Expected 401, got %d", rr.Code)
						return false
					}
				}
			}

			// No drafts should be created from cross-user attempts
			if draftStore.GetDraftCount() != 0 {
				t.Logf("Expected 0 drafts from cross-user attempts, got %d", draftStore.GetDraftCount())
				return false
			}

			return true
		},
		gen.IntRange(2, 10),
	))

	properties.TestingRun(t)
}

// TestProperty_MultiTenantSameCommitDifferentDrafts verifies same commit creates separate drafts per user
func TestProperty_MultiTenantSameCommitDifferentDrafts(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 25

	properties := gopter.NewProperties(parameters)

	properties.Property("same GitHub commit creates N separate drafts for N users", prop.ForAll(
		func(numUsers int, commitID string) bool {
			repoStore := NewMockMultiTenantRepoStore()
			draftStore := NewMockMultiTenantDraftStore()
			aiGenerator := NewMockPersonalizedAIGenerator()
			githubRepoURL := "https://github.com/shared/commit-test"

			// Setup
			var repos []*Repository
			var handlers []*DraftCreatingWebhookHandler
			var idempotencyStores []*MockMultiTenantIdempotencyStore

			for i := 0; i < numUsers; i++ {
				secretBytes := make([]byte, 32)
				rand.Read(secretBytes)

				repo := &Repository{
					ID:            fmt.Sprintf("repo-%d", i),
					UserID:        fmt.Sprintf("user-%d", i),
					GitHubURL:     githubRepoURL,
					WebhookSecret: hex.EncodeToString(secretBytes),
					CreatedAt:     time.Now(),
				}
				repoStore.AddRepository(repo)
				repos = append(repos, repo)

				idempStore := NewMockMultiTenantIdempotencyStore()
				idempotencyStores = append(idempotencyStores, idempStore)

				handler := NewDraftCreatingWebhookHandler(repoStore, draftStore, idempStore).
					WithAIGenerator(aiGenerator)
				handlers = append(handlers, handler)
			}

			// Use the SAME commit SHA for all users (same push)
			beforeSHA := "0000000000000000000000000000000000000000"
			afterSHA := "abcdef1234567890abcdef1234567890abcdef12"

			payload := createPushPayloadWithSHAs(beforeSHA, afterSHA, []map[string]interface{}{
				{"id": commitID, "message": "shared commit", "author": map[string]interface{}{"name": "Dev"}},
			})

			for i := 0; i < numUsers; i++ {
				sig := generateGitHubSignature(payload, repos[i].WebhookSecret)
				req := createDraftWebhookRequest(t, repos[i].ID, payload, sig, fmt.Sprintf("delivery-%d", i))
				req.Header.Set("X-GitHub-Event", "push")

				rr := httptest.NewRecorder()
				handlers[i].ServeHTTP(rr, req)

				if rr.Code != http.StatusOK {
					return false
				}
			}

			// Verify N drafts created
			allDrafts := draftStore.GetAllDrafts()
			if len(allDrafts) != numUsers {
				t.Logf("Expected %d drafts, got %d", numUsers, len(allDrafts))
				return false
			}

			// Verify all drafts reference the same commit
			for _, draft := range allDrafts {
				if len(draft.CommitSHAs) != 1 || draft.CommitSHAs[0] != commitID {
					t.Logf("Draft %s has unexpected commit SHAs: %v", draft.ID, draft.CommitSHAs)
					return false
				}
				if draft.AfterSHA != afterSHA {
					t.Logf("Draft %s has unexpected AfterSHA: %s", draft.ID, draft.AfterSHA)
					return false
				}
			}

			return true
		},
		gen.IntRange(2, 25),
		gen.RegexMatch(`[a-f0-9]{40}`), // Valid Git commit SHA format
	))

	properties.TestingRun(t)
}
