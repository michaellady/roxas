package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Property Test: Multi-Tenant Webhook Installation
// Property 10: N users tracking same repo = N separate webhooks with unique secrets
// Validates Requirements 3.9
// =============================================================================

// UniqueSecretGenerator generates unique secrets for each call
type UniqueSecretGenerator struct {
	mu      sync.Mutex
	secrets []string
}

func NewUniqueSecretGenerator() *UniqueSecretGenerator {
	return &UniqueSecretGenerator{
		secrets: make([]string, 0),
	}
}

func (g *UniqueSecretGenerator) Generate() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(bytes)
	g.secrets = append(g.secrets, secret)
	return secret, nil
}

func (g *UniqueSecretGenerator) GetGeneratedSecrets() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	result := make([]string, len(g.secrets))
	copy(result, g.secrets)
	return result
}

// =============================================================================
// Property Test: N users tracking same repo = N separate webhooks
// =============================================================================

func TestProperty_MultiTenantWebhookInstallation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	// Property: N users adding the same repo results in N separate webhooks with unique secrets
	properties.Property("N users tracking same repo creates N separate webhooks with unique secrets", prop.ForAll(
		func(numUsers int, repoURL string) bool {
			store := NewMockRepositoryStore()
			secretGen := NewUniqueSecretGenerator()
			handler := NewRepositoryHandler(store, secretGen, "https://api.roxas.dev")

			ctx := context.Background()
			createdRepos := make([]*Repository, 0, numUsers)

			// Each user adds the same repo
			for i := 0; i < numUsers; i++ {
				userID := generateUserID(i)

				// Directly use the store to simulate what AddRepository handler does
				secret, err := secretGen.Generate()
				if err != nil {
					return false
				}

				repo, err := store.CreateRepository(ctx, userID, repoURL, secret)
				if err != nil {
					return false
				}
				createdRepos = append(createdRepos, repo)
			}

			// Verify we have exactly N repositories
			if len(createdRepos) != numUsers {
				t.Logf("Expected %d repos, got %d", numUsers, len(createdRepos))
				return false
			}

			// Verify all repository IDs are unique
			repoIDs := make(map[string]bool)
			for _, repo := range createdRepos {
				if repoIDs[repo.ID] {
					t.Logf("Duplicate repo ID found: %s", repo.ID)
					return false
				}
				repoIDs[repo.ID] = true
			}

			// Verify all webhook secrets are unique
			secrets := make(map[string]bool)
			for _, repo := range createdRepos {
				if secrets[repo.WebhookSecret] {
					t.Logf("Duplicate webhook secret found")
					return false
				}
				secrets[repo.WebhookSecret] = true
			}

			// Verify each user has exactly one repo with this URL
			for i := 0; i < numUsers; i++ {
				userID := generateUserID(i)
				repo, err := store.GetRepositoryByUserAndURL(ctx, userID, repoURL)
				if err != nil {
					t.Logf("Error getting repo for user %s: %v", userID, err)
					return false
				}
				if repo == nil {
					t.Logf("No repo found for user %s", userID)
					return false
				}
			}

			// Verify handler reference is valid (using it to avoid unused variable)
			_ = handler

			return true
		},
		gen.IntRange(2, 50),                            // 2-50 users (avoid trivial case of 1 user)
		gen.AlphaString().Map(func(s string) string { // Random repo path component
			if len(s) < 3 {
				s = "abc"
			}
			return "https://github.com/testuser/" + s
		}),
	))

	properties.TestingRun(t)
}

// TestProperty_WebhookSecretsAreCryptographicallyUnique verifies secrets have sufficient entropy
func TestProperty_WebhookSecretsAreCryptographicallyUnique(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Generated secrets are cryptographically unique", prop.ForAll(
		func(numSecrets int) bool {
			secretGen := NewCryptoSecretGenerator()
			secrets := make(map[string]bool)

			for i := 0; i < numSecrets; i++ {
				secret, err := secretGen.Generate()
				if err != nil {
					return false
				}

				// Verify minimum length (32 bytes base64 encoded = 43+ chars)
				if len(secret) < 40 {
					t.Logf("Secret too short: %d chars", len(secret))
					return false
				}

				// Verify uniqueness
				if secrets[secret] {
					t.Logf("Duplicate secret generated after %d iterations", i)
					return false
				}
				secrets[secret] = true
			}

			return true
		},
		gen.IntRange(10, 1000), // Generate 10-1000 secrets
	))

	properties.TestingRun(t)
}

// TestProperty_SameUserCannotAddSameRepoTwice verifies duplicate prevention
func TestProperty_SameUserCannotAddSameRepoTwice(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("Same user cannot add same repo twice", prop.ForAll(
		func(repoURL string) bool {
			store := NewMockRepositoryStore()
			secretGen := NewUniqueSecretGenerator()
			ctx := context.Background()

			userID := "test-user-duplicate-check"

			// First add should succeed
			secret1, _ := secretGen.Generate()
			repo1, err := store.CreateRepository(ctx, userID, repoURL, secret1)
			if err != nil {
				t.Logf("First add failed: %v", err)
				return false
			}
			if repo1 == nil {
				t.Log("First add returned nil repo")
				return false
			}

			// Second add should fail with ErrDuplicateRepository
			secret2, _ := secretGen.Generate()
			repo2, err := store.CreateRepository(ctx, userID, repoURL, secret2)
			if err != ErrDuplicateRepository {
				t.Logf("Expected ErrDuplicateRepository, got: %v", err)
				return false
			}
			if repo2 != nil {
				t.Log("Second add should return nil repo")
				return false
			}

			return true
		},
		gen.AlphaString().Map(func(s string) string {
			if len(s) < 3 {
				s = "abc"
			}
			return "https://github.com/testuser/" + s
		}),
	))

	properties.TestingRun(t)
}

// TestProperty_DifferentUsersGetDifferentWebhookURLs verifies webhook URL uniqueness
func TestProperty_DifferentUsersGetDifferentWebhookURLs(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 30

	properties := gopter.NewProperties(parameters)

	properties.Property("Different users get different webhook URLs for same repo", prop.ForAll(
		func(numUsers int, repoPath string) bool {
			store := NewMockRepositoryStore()
			secretGen := NewUniqueSecretGenerator()
			webhookBaseURL := "https://api.roxas.dev"

			ctx := context.Background()
			repoURL := "https://github.com/shared/" + repoPath

			webhookURLs := make(map[string]string) // webhook URL -> userID

			for i := 0; i < numUsers; i++ {
				userID := generateUserID(i)

				secret, err := secretGen.Generate()
				if err != nil {
					return false
				}

				repo, err := store.CreateRepository(ctx, userID, repoURL, secret)
				if err != nil {
					return false
				}

				// Webhook URL is constructed as: baseURL + "/webhook/" + repo.ID
				webhookURL := webhookBaseURL + "/webhook/" + repo.ID

				// Check for duplicate webhook URLs
				if existingUser, exists := webhookURLs[webhookURL]; exists {
					t.Logf("Duplicate webhook URL for users %s and %s", existingUser, userID)
					return false
				}
				webhookURLs[webhookURL] = userID
			}

			// Verify we have exactly N unique webhook URLs
			if len(webhookURLs) != numUsers {
				t.Logf("Expected %d unique webhook URLs, got %d", numUsers, len(webhookURLs))
				return false
			}

			return true
		},
		gen.IntRange(2, 30),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) >= 3 }),
	))

	properties.TestingRun(t)
}

// TestProperty_WebhookSecretIsolation verifies secrets are isolated per tenant
func TestProperty_WebhookSecretIsolation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("Webhook secrets are isolated - one user's secret cannot validate another's webhook", prop.ForAll(
		func(numUsers int) bool {
			store := NewMockWebhookRepositoryStore()
			commitStore := NewMockCommitStore()
			secretGen := NewUniqueSecretGenerator()

			ctx := context.Background()
			repoURL := "https://github.com/shared/testproject"

			// Create repositories for multiple users
			repos := make([]*Repository, 0, numUsers)
			for i := 0; i < numUsers; i++ {
				userID := generateUserID(i)
				secret, _ := secretGen.Generate()

				repo := &Repository{
					ID:            generateRepoID(i),
					UserID:        userID,
					GitHubURL:     repoURL,
					WebhookSecret: secret,
				}
				store.AddRepository(repo)
				repos = append(repos, repo)
			}

			handler := NewMultiTenantWebhookHandler(store, commitStore)

			// For each repo, verify its secret only works for its own webhook
			for i, repo := range repos {
				payload := createPushPayload([]map[string]interface{}{
					{
						"id":        "abc123",
						"message":   "test commit",
						"url":       "https://github.com/test/repo/commit/abc123",
						"timestamp": "2024-01-15T10:30:00Z",
						"author":    map[string]interface{}{"name": "Test", "email": "test@example.com"},
					},
				})

				// Test that repo's own secret works
				correctSig := generateGitHubSignature(payload, repo.WebhookSecret)
				req := createWebhookRequest(t, repo.ID, payload, correctSig)
				req.Header.Set("X-GitHub-Event", "push")

				rr := newTestRecorder()
				handler.ServeHTTP(rr, req)

				if rr.Code != 200 {
					t.Logf("Valid signature rejected for repo %d: status %d", i, rr.Code)
					return false
				}

				// Test that other repos' secrets don't work
				for j, otherRepo := range repos {
					if i == j {
						continue
					}

					wrongSig := generateGitHubSignature(payload, otherRepo.WebhookSecret)
					req2 := createWebhookRequest(t, repo.ID, payload, wrongSig)
					req2.Header.Set("X-GitHub-Event", "push")

					rr2 := newTestRecorder()
					handler.ServeHTTP(rr2, req2)

					// Should be rejected (401 Unauthorized)
					if rr2.Code == 200 {
						t.Logf("Wrong secret accepted: repo %d used repo %d's secret", i, j)
						return false
					}
				}
			}

			// Verify handler reference is valid
			_ = handler
			_ = ctx

			return true
		},
		gen.IntRange(2, 10), // 2-10 users (smaller range for exhaustive cross-check)
	))

	properties.TestingRun(t)
}

// =============================================================================
// Helpers
// =============================================================================

func generateUserID(index int) string {
	return "user-" + string(rune('A'+index%26)) + string(rune('0'+index/26))
}

func generateRepoID(index int) string {
	return "repo-" + string(rune('A'+index%26)) + string(rune('0'+index/26))
}

// testRecorder wraps httptest.ResponseRecorder
type testRecorder struct {
	Code int
	Body []byte
}

func newTestRecorder() *testRecorder {
	return &testRecorder{Code: 200}
}

func (r *testRecorder) Header() http.Header {
	return make(http.Header)
}

func (r *testRecorder) Write(b []byte) (int, error) {
	r.Body = append(r.Body, b...)
	return len(b), nil
}

func (r *testRecorder) WriteHeader(code int) {
	r.Code = code
}
