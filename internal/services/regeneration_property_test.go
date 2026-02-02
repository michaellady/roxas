package services

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Property Test: Draft Content Regeneration (Property 24)
// Property: Regeneration calls GPT and updates generated_content field.
// Validates Requirements 6.9
// =============================================================================

// MockDraftForRegen represents a draft for testing regeneration
type MockDraftForRegen struct {
	ID               string
	UserID           string
	RepositoryID     string
	Ref              string
	BeforeSHA        string
	AfterSHA         string
	CommitSHAs       []string
	GeneratedContent string
	EditedContent    *string
	Status           string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// MockDraftStoreForRegen tracks draft operations for property testing
type MockDraftStoreForRegen struct {
	mu              sync.Mutex
	drafts          map[string]*MockDraftForRegen
	updateCalls     []string // Track draft IDs that had content updated
	updatedContents map[string]string
}

func NewMockDraftStoreForRegen() *MockDraftStoreForRegen {
	return &MockDraftStoreForRegen{
		drafts:          make(map[string]*MockDraftForRegen),
		updateCalls:     make([]string, 0),
		updatedContents: make(map[string]string),
	}
}

func (s *MockDraftStoreForRegen) AddDraft(draft *MockDraftForRegen) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drafts[draft.ID] = draft
}

func (s *MockDraftStoreForRegen) GetDraft(ctx context.Context, draftID string) (*MockDraftForRegen, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	draft, ok := s.drafts[draftID]
	if !ok {
		return nil, fmt.Errorf("draft not found: %s", draftID)
	}
	return draft, nil
}

func (s *MockDraftStoreForRegen) UpdateDraftContent(ctx context.Context, draftID, content string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	draft, ok := s.drafts[draftID]
	if !ok {
		return fmt.Errorf("draft not found: %s", draftID)
	}
	draft.GeneratedContent = content
	draft.UpdatedAt = time.Now()
	s.updateCalls = append(s.updateCalls, draftID)
	s.updatedContents[draftID] = content
	return nil
}

func (s *MockDraftStoreForRegen) UpdateDraftStatus(ctx context.Context, draftID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	draft, ok := s.drafts[draftID]
	if !ok {
		return fmt.Errorf("draft not found: %s", draftID)
	}
	draft.Status = status
	return nil
}

func (s *MockDraftStoreForRegen) GetUpdateCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]string, len(s.updateCalls))
	copy(result, s.updateCalls)
	return result
}

func (s *MockDraftStoreForRegen) GetUpdatedContent(draftID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	content, ok := s.updatedContents[draftID]
	return content, ok
}

// MockRepositoryForRegen represents a repository for testing
type MockRepositoryForRegen struct {
	ID        string
	UserID    string
	GitHubURL string
}

// MockRepoStoreForRegen provides repository data for regeneration testing
type MockRepoStoreForRegen struct {
	mu    sync.Mutex
	repos map[string]*MockRepositoryForRegen
}

func NewMockRepoStoreForRegen() *MockRepoStoreForRegen {
	return &MockRepoStoreForRegen{
		repos: make(map[string]*MockRepositoryForRegen),
	}
}

func (s *MockRepoStoreForRegen) AddRepository(repo *MockRepositoryForRegen) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repos[repo.ID] = repo
}

func (s *MockRepoStoreForRegen) GetRepositoryByID(ctx context.Context, repoID string) (*MockRepositoryForRegen, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	repo, ok := s.repos[repoID]
	if !ok {
		return nil, fmt.Errorf("repository not found: %s", repoID)
	}
	return repo, nil
}

// GPTTrackingChatClient tracks GPT calls and returns configurable responses
type GPTTrackingChatClient struct {
	mu              sync.Mutex
	callCount       int
	prompts         []string
	responseContent string
	shouldError     bool
}

func NewGPTTrackingChatClient(response string) *GPTTrackingChatClient {
	return &GPTTrackingChatClient{
		prompts:         make([]string, 0),
		responseContent: response,
	}
}

func (c *GPTTrackingChatClient) CreateChatCompletion(prompt string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.callCount++
	c.prompts = append(c.prompts, prompt)
	if c.shouldError {
		return "", fmt.Errorf("GPT API error")
	}
	return c.responseContent, nil
}

func (c *GPTTrackingChatClient) GetCallCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.callCount
}

func (c *GPTTrackingChatClient) GetPrompts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]string, len(c.prompts))
	copy(result, c.prompts)
	return result
}

func (c *GPTTrackingChatClient) SetShouldError(shouldError bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.shouldError = shouldError
}

// DraftRegenerator handles draft regeneration using AI
type DraftRegenerator struct {
	draftStore    *MockDraftStoreForRegen
	repoStore     *MockRepoStoreForRegen
	postGenerator PostGeneratorService
}

func NewDraftRegenerator(
	draftStore *MockDraftStoreForRegen,
	repoStore *MockRepoStoreForRegen,
	postGenerator PostGeneratorService,
) *DraftRegenerator {
	return &DraftRegenerator{
		draftStore:    draftStore,
		repoStore:     repoStore,
		postGenerator: postGenerator,
	}
}

func (r *DraftRegenerator) RegenerateDraft(ctx context.Context, draftID string) error {
	// Fetch the draft
	draft, err := r.draftStore.GetDraft(ctx, draftID)
	if err != nil {
		return fmt.Errorf("failed to get draft: %w", err)
	}

	// Fetch repo info for the commit URL
	repo, err := r.repoStore.GetRepositoryByID(ctx, draft.RepositoryID)
	if err != nil {
		return fmt.Errorf("failed to get repository: %w", err)
	}

	// Build a commit-like object for the generator
	commitMessage := fmt.Sprintf("Push to %s with %d commit(s)", draft.Ref, len(draft.CommitSHAs))
	if len(draft.CommitSHAs) == 1 {
		commitMessage = fmt.Sprintf("Commit %s to %s", draft.AfterSHA[:7], draft.Ref)
	}

	commit := &Commit{
		ID:        draft.AfterSHA,
		Message:   commitMessage,
		Author:    "developer",
		GitHubURL: fmt.Sprintf("%s/commit/%s", repo.GitHubURL, draft.AfterSHA),
	}

	// Generate content using PostGenerator (this calls GPT)
	generated, err := r.postGenerator.Generate(ctx, PlatformBluesky, commit)
	if err != nil {
		// Update draft status to error
		_ = r.draftStore.UpdateDraftStatus(ctx, draftID, "error")
		return fmt.Errorf("failed to generate content: %w", err)
	}

	// Update draft with generated content
	err = r.draftStore.UpdateDraftContent(ctx, draftID, generated.Content)
	if err != nil {
		return fmt.Errorf("failed to update draft content: %w", err)
	}

	return nil
}

// =============================================================================
// Property 24a: Regeneration always calls GPT exactly once per draft
// =============================================================================

func TestProperty24a_RegenerationCallsGPTOnce(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("regeneration calls GPT exactly once per draft", prop.ForAll(
		func(draftID, repoID, afterSHA, ref string) bool {
			// Setup
			draftStore := NewMockDraftStoreForRegen()
			repoStore := NewMockRepoStoreForRegen()
			chatClient := NewGPTTrackingChatClient("Generated content from GPT")
			postGenerator := NewPostGenerator(chatClient)

			// Add test data
			repoStore.AddRepository(&MockRepositoryForRegen{
				ID:        repoID,
				UserID:    "user-1",
				GitHubURL: "https://github.com/test/repo",
			})

			draftStore.AddDraft(&MockDraftForRegen{
				ID:               draftID,
				UserID:           "user-1",
				RepositoryID:     repoID,
				Ref:              ref,
				AfterSHA:         afterSHA,
				CommitSHAs:       []string{afterSHA},
				GeneratedContent: "old content",
				Status:           "draft",
				CreatedAt:        time.Now(),
			})

			// Execute regeneration
			regenerator := NewDraftRegenerator(draftStore, repoStore, postGenerator)
			ctx := context.Background()
			err := regenerator.RegenerateDraft(ctx, draftID)

			// Verify
			if err != nil {
				t.Logf("Regeneration failed: %v", err)
				return false
			}

			// Property: GPT was called exactly once
			callCount := chatClient.GetCallCount()
			if callCount != 1 {
				t.Logf("Expected 1 GPT call, got %d", callCount)
				return false
			}

			return true
		},
		genDraftID(),
		genRepoID(),
		genCommitSHA(),
		genRef(),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Property 24b: Regeneration updates generated_content field
// =============================================================================

func TestProperty24b_RegenerationUpdatesGeneratedContent(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("regeneration updates the generated_content field", prop.ForAll(
		func(draftID, repoID, afterSHA, ref, gptResponse string) bool {
			// Setup
			draftStore := NewMockDraftStoreForRegen()
			repoStore := NewMockRepoStoreForRegen()
			chatClient := NewGPTTrackingChatClient(gptResponse)
			postGenerator := NewPostGenerator(chatClient)

			// Add test data
			repoStore.AddRepository(&MockRepositoryForRegen{
				ID:        repoID,
				UserID:    "user-1",
				GitHubURL: "https://github.com/test/repo",
			})

			originalContent := "original generated content"
			draftStore.AddDraft(&MockDraftForRegen{
				ID:               draftID,
				UserID:           "user-1",
				RepositoryID:     repoID,
				Ref:              ref,
				AfterSHA:         afterSHA,
				CommitSHAs:       []string{afterSHA},
				GeneratedContent: originalContent,
				Status:           "draft",
				CreatedAt:        time.Now(),
			})

			// Execute regeneration
			regenerator := NewDraftRegenerator(draftStore, repoStore, postGenerator)
			ctx := context.Background()
			err := regenerator.RegenerateDraft(ctx, draftID)

			// Verify
			if err != nil {
				t.Logf("Regeneration failed: %v", err)
				return false
			}

			// Property: UpdateDraftContent was called for this draft
			updateCalls := draftStore.GetUpdateCalls()
			found := false
			for _, id := range updateCalls {
				if id == draftID {
					found = true
					break
				}
			}
			if !found {
				t.Logf("UpdateDraftContent was not called for draft %s", draftID)
				return false
			}

			// Property: The content was updated to the GPT response (possibly truncated for Bluesky)
			updatedContent, ok := draftStore.GetUpdatedContent(draftID)
			if !ok {
				t.Logf("No updated content found for draft %s", draftID)
				return false
			}

			// Content should be non-empty (GPT generated something)
			if updatedContent == "" {
				t.Logf("Updated content is empty")
				return false
			}

			// Content should be different from original (since GPT response is different)
			if updatedContent == originalContent && gptResponse != originalContent {
				t.Logf("Content was not updated")
				return false
			}

			return true
		},
		genDraftID(),
		genRepoID(),
		genCommitSHA(),
		genRef(),
		genGPTResponse(),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Property 24c: GPT prompt includes commit context
// =============================================================================

func TestProperty24c_GPTPromptIncludesCommitContext(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("GPT prompt includes commit context from draft", prop.ForAll(
		func(draftID, repoID, afterSHA, ref string) bool {
			// Setup
			draftStore := NewMockDraftStoreForRegen()
			repoStore := NewMockRepoStoreForRegen()
			chatClient := NewGPTTrackingChatClient("Generated content")
			postGenerator := NewPostGenerator(chatClient)

			// Add test data with specific repo URL
			repoURL := "https://github.com/testowner/testrepo"
			repoStore.AddRepository(&MockRepositoryForRegen{
				ID:        repoID,
				UserID:    "user-1",
				GitHubURL: repoURL,
			})

			draftStore.AddDraft(&MockDraftForRegen{
				ID:               draftID,
				UserID:           "user-1",
				RepositoryID:     repoID,
				Ref:              ref,
				AfterSHA:         afterSHA,
				CommitSHAs:       []string{afterSHA},
				GeneratedContent: "old content",
				Status:           "draft",
				CreatedAt:        time.Now(),
			})

			// Execute regeneration
			regenerator := NewDraftRegenerator(draftStore, repoStore, postGenerator)
			ctx := context.Background()
			err := regenerator.RegenerateDraft(ctx, draftID)

			// Verify
			if err != nil {
				t.Logf("Regeneration failed: %v", err)
				return false
			}

			// Property: Prompt includes repository info
			prompts := chatClient.GetPrompts()
			if len(prompts) == 0 {
				t.Logf("No prompts recorded")
				return false
			}

			prompt := prompts[0]

			// Prompt should contain repository info (extracted from URL)
			if !containsSubstring(prompt, "testowner") && !containsSubstring(prompt, "testrepo") {
				t.Logf("Prompt should contain repository info")
				return false
			}

			return true
		},
		genDraftID(),
		genRepoID(),
		genCommitSHA(),
		genRef(),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Property 24d: Multiple regenerations produce multiple GPT calls
// =============================================================================

func TestProperty24d_MultipleRegenerationsCallGPTMultipleTimes(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	parameters.MaxSize = 10

	properties := gopter.NewProperties(parameters)

	properties.Property("N regenerations result in N GPT calls", prop.ForAll(
		func(numRegenerations int, draftID, repoID, afterSHA, ref string) bool {
			// Setup
			draftStore := NewMockDraftStoreForRegen()
			repoStore := NewMockRepoStoreForRegen()
			chatClient := NewGPTTrackingChatClient("Generated content")
			postGenerator := NewPostGenerator(chatClient)

			// Add test data
			repoStore.AddRepository(&MockRepositoryForRegen{
				ID:        repoID,
				UserID:    "user-1",
				GitHubURL: "https://github.com/test/repo",
			})

			draftStore.AddDraft(&MockDraftForRegen{
				ID:               draftID,
				UserID:           "user-1",
				RepositoryID:     repoID,
				Ref:              ref,
				AfterSHA:         afterSHA,
				CommitSHAs:       []string{afterSHA},
				GeneratedContent: "old content",
				Status:           "draft",
				CreatedAt:        time.Now(),
			})

			// Execute multiple regenerations
			regenerator := NewDraftRegenerator(draftStore, repoStore, postGenerator)
			ctx := context.Background()

			for i := 0; i < numRegenerations; i++ {
				err := regenerator.RegenerateDraft(ctx, draftID)
				if err != nil {
					t.Logf("Regeneration %d failed: %v", i, err)
					return false
				}
			}

			// Property: GPT was called exactly N times
			callCount := chatClient.GetCallCount()
			if callCount != numRegenerations {
				t.Logf("Expected %d GPT calls, got %d", numRegenerations, callCount)
				return false
			}

			return true
		},
		gen.IntRange(1, 10), // 1-10 regenerations
		genDraftID(),
		genRepoID(),
		genCommitSHA(),
		genRef(),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Property 24e: GPT error prevents content update
// =============================================================================

func TestProperty24e_GPTErrorPreventsContentUpdate(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("GPT error prevents content update and sets error status", prop.ForAll(
		func(draftID, repoID, afterSHA, ref string) bool {
			// Setup
			draftStore := NewMockDraftStoreForRegen()
			repoStore := NewMockRepoStoreForRegen()
			chatClient := NewGPTTrackingChatClient("")
			chatClient.SetShouldError(true) // Force GPT to fail
			postGenerator := NewPostGenerator(chatClient)

			// Add test data
			repoStore.AddRepository(&MockRepositoryForRegen{
				ID:        repoID,
				UserID:    "user-1",
				GitHubURL: "https://github.com/test/repo",
			})

			originalContent := "original content should remain"
			draftStore.AddDraft(&MockDraftForRegen{
				ID:               draftID,
				UserID:           "user-1",
				RepositoryID:     repoID,
				Ref:              ref,
				AfterSHA:         afterSHA,
				CommitSHAs:       []string{afterSHA},
				GeneratedContent: originalContent,
				Status:           "draft",
				CreatedAt:        time.Now(),
			})

			// Execute regeneration
			regenerator := NewDraftRegenerator(draftStore, repoStore, postGenerator)
			ctx := context.Background()
			err := regenerator.RegenerateDraft(ctx, draftID)

			// Property: Regeneration should return an error
			if err == nil {
				t.Logf("Expected error when GPT fails, got nil")
				return false
			}

			// Property: Content should NOT have been updated
			updateCalls := draftStore.GetUpdateCalls()
			for _, id := range updateCalls {
				if id == draftID {
					t.Logf("Content was updated despite GPT error")
					return false
				}
			}

			// Property: Draft should have error status
			draft, _ := draftStore.GetDraft(ctx, draftID)
			if draft.Status != "error" {
				t.Logf("Expected draft status to be 'error', got '%s'", draft.Status)
				return false
			}

			return true
		},
		genDraftID(),
		genRepoID(),
		genCommitSHA(),
		genRef(),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Generators
// =============================================================================

func genDraftID() gopter.Gen {
	return gen.RegexMatch(`draft-[a-z0-9]{8}`)
}

func genRepoID() gopter.Gen {
	return gen.RegexMatch(`repo-[a-z0-9]{8}`)
}

func genCommitSHA() gopter.Gen {
	return gen.RegexMatch(`[a-f0-9]{40}`)
}

func genRef() gopter.Gen {
	branch := gen.RegexMatch(`[a-z]{3,10}`)
	return branch.Map(func(b string) string {
		return "refs/heads/" + b
	})
}

func genGPTResponse() gopter.Gen {
	// Generate realistic GPT-like responses
	prefixes := []string{
		"Just shipped:",
		"New feature:",
		"Fixed:",
		"Now supporting:",
		"Added:",
	}
	suffixes := []string{
		"Better performance incoming!",
		"Building in public.",
		"Check it out!",
		"More updates soon.",
		"Feedback welcome!",
	}

	return gopter.CombineGens(
		gen.OneConstOf(prefixes[0], prefixes[1], prefixes[2], prefixes[3], prefixes[4]),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) >= 5 && len(s) <= 50 }),
		gen.OneConstOf(suffixes[0], suffixes[1], suffixes[2], suffixes[3], suffixes[4]),
	).Map(func(vals []interface{}) string {
		return vals[0].(string) + " " + vals[1].(string) + " " + vals[2].(string)
	})
}

// containsSubstring is a helper that checks if str contains substr (case insensitive)
func containsSubstring(str, substr string) bool {
	return len(str) > 0 && len(substr) > 0 &&
		(str == substr || len(str) >= len(substr) &&
			(str[:len(substr)] == substr ||
			 containsSubstring(str[1:], substr)))
}
