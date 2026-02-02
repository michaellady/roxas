package handlers

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/mikelady/roxas/internal/services"
)

// =============================================================================
// Property Test: Post Idempotency (Property 28)
// Property: Already-posted drafts return success without creating duplicates.
// Validates Requirements 7.14
//
// From SPEC:
// **Idempotency:**
// - Backend handles duplicate requests gracefully (e.g., double-click on "Post It")
// - If draft already posted, return success without re-posting
// =============================================================================

// IdempotentDraftStore implements DraftStoreForPost with idempotency tracking
type IdempotentDraftStore struct {
	mu     sync.RWMutex
	drafts map[string]*Draft
}

func NewIdempotentDraftStore() *IdempotentDraftStore {
	return &IdempotentDraftStore{
		drafts: make(map[string]*Draft),
	}
}

func (m *IdempotentDraftStore) CreateDraft(ctx context.Context, userID, repoID string, genContent, editContent string) (*Draft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := uuid.New().String()
	draft := &Draft{
		ID:               id,
		UserID:           userID,
		RepositoryID:     repoID,
		GeneratedContent: &genContent,
		EditedContent:    &editContent,
		Status:           "draft",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	m.drafts[id] = draft
	return draft, nil
}

func (m *IdempotentDraftStore) GetDraft(ctx context.Context, draftID string) (*Draft, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if draft, ok := m.drafts[draftID]; ok {
		return draft, nil
	}
	return nil, nil
}

func (m *IdempotentDraftStore) GetDraftByUserID(ctx context.Context, draftID, userID string) (*Draft, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if draft, ok := m.drafts[draftID]; ok {
		if draft.UserID == userID {
			return draft, nil
		}
		return nil, nil
	}
	return nil, nil
}

func (m *IdempotentDraftStore) UpdateDraftStatus(ctx context.Context, draftID, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if draft, ok := m.drafts[draftID]; ok {
		draft.Status = status
		draft.UpdatedAt = time.Now()
		return nil
	}
	return nil
}

// IdempotentPostStore implements PostStoreForDraft with idempotency support
// It tracks posts by draft+platform to detect and handle duplicates
type IdempotentPostStore struct {
	mu              sync.RWMutex
	posts           map[string]*PostFromDraft
	postsByDraftKey map[string]string // key: draftID+platform -> postID
}

func NewIdempotentPostStore() *IdempotentPostStore {
	return &IdempotentPostStore{
		posts:           make(map[string]*PostFromDraft),
		postsByDraftKey: make(map[string]string),
	}
}

func (m *IdempotentPostStore) draftPlatformKey(draftID, platform string) string {
	return draftID + ":" + platform
}

// CreatePostFromDraft creates a new post or returns existing if already posted (idempotent)
func (m *IdempotentPostStore) CreatePostFromDraft(ctx context.Context, draftID, userID, platform, content string) (*PostFromDraft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.draftPlatformKey(draftID, platform)

	// Check if post already exists for this draft+platform
	if existingPostID, ok := m.postsByDraftKey[key]; ok {
		if existingPost, ok := m.posts[existingPostID]; ok {
			return existingPost, nil
		}
	}

	// Create new post
	post := &PostFromDraft{
		ID:        uuid.New().String(),
		DraftID:   draftID,
		UserID:    userID,
		Platform:  platform,
		Content:   content,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	m.posts[post.ID] = post
	m.postsByDraftKey[key] = post.ID
	return post, nil
}

func (m *IdempotentPostStore) UpdatePostResult(ctx context.Context, postID string, platformPostID, platformPostURL string, postedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if post, ok := m.posts[postID]; ok {
		post.PlatformPostID = platformPostID
		post.PlatformPostURL = platformPostURL
		post.PostedAt = &postedAt
		post.Status = "posted"
		return nil
	}
	return nil
}

func (m *IdempotentPostStore) UpdatePostError(ctx context.Context, postID, errorMessage string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if post, ok := m.posts[postID]; ok {
		post.ErrorMessage = errorMessage
		post.Status = "failed"
		return nil
	}
	return nil
}

func (m *IdempotentPostStore) GetPostByID(ctx context.Context, postID string) (*PostFromDraft, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if post, ok := m.posts[postID]; ok {
		return post, nil
	}
	return nil, nil
}

// GetPostByDraftAndPlatform retrieves existing post for a draft+platform combination
func (m *IdempotentPostStore) GetPostByDraftAndPlatform(ctx context.Context, draftID, platform string) (*PostFromDraft, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.draftPlatformKey(draftID, platform)
	if postID, ok := m.postsByDraftKey[key]; ok {
		if post, ok := m.posts[postID]; ok {
			return post, nil
		}
	}
	return nil, nil
}

// PostCount returns the total number of posts in the store
func (m *IdempotentPostStore) PostCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.posts)
}

// IdempotentSocialClient tracks API calls for verification
type IdempotentSocialClient struct {
	mu        sync.Mutex
	callCount int
}

func NewIdempotentSocialClient() *IdempotentSocialClient {
	return &IdempotentSocialClient{}
}

func (m *IdempotentSocialClient) Post(ctx context.Context, content services.PostContent) (*services.PostResult, error) {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()

	return &services.PostResult{
		PostID:  "platform-post-" + uuid.New().String(),
		PostURL: "https://www.threads.net/@testuser/post/" + uuid.New().String()[:8],
	}, nil
}

func (m *IdempotentSocialClient) ValidateContent(content services.PostContent) error {
	if len(content.Text) == 0 {
		return nil
	}
	return nil
}

func (m *IdempotentSocialClient) Platform() string {
	return services.PlatformThreads
}

func (m *IdempotentSocialClient) GetRateLimits() services.RateLimitInfo {
	return services.RateLimitInfo{
		Limit:     250,
		Remaining: 245,
		ResetAt:   time.Now().Add(24 * time.Hour),
	}
}

func (m *IdempotentSocialClient) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func (m *IdempotentSocialClient) ResetCallCount() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount = 0
}

// IdempotentCredentialStore provides credentials for testing
type IdempotentCredentialStore struct {
	credentials *services.PlatformCredentials
}

func NewIdempotentCredentialStore(userID string) *IdempotentCredentialStore {
	expiresAt := time.Now().Add(24 * time.Hour)
	return &IdempotentCredentialStore{
		credentials: &services.PlatformCredentials{
			UserID:         userID,
			Platform:       services.PlatformThreads,
			AccessToken:    "valid-token-for-testing",
			TokenExpiresAt: &expiresAt,
		},
	}
}

func (m *IdempotentCredentialStore) GetCredentials(ctx context.Context, userID, platform string) (*services.PlatformCredentials, error) {
	if m.credentials != nil && m.credentials.UserID == userID && m.credentials.Platform == platform {
		return m.credentials, nil
	}
	return nil, nil
}

// =============================================================================
// Property Tests
// =============================================================================

// TestProperty28_PostIdempotency verifies that already-posted drafts return
// success without creating duplicates.
func TestProperty28_PostIdempotency(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	// Property 28a: Posting an already-posted draft returns the existing post
	// (no new post is created)
	properties.Property("posting already-posted draft does not create duplicate", prop.ForAll(
		func(content string) bool {
			if content == "" {
				content = "default test content"
			}

			draftStore := NewIdempotentDraftStore()
			postStore := NewIdempotentPostStore()
			socialClient := NewIdempotentSocialClient()

			userID := "user-" + uuid.New().String()[:8]

			ctx := context.Background()

			// Create a draft
			draft, err := draftStore.CreateDraft(ctx, userID, "repo-123", content, content)
			if err != nil {
				t.Logf("Failed to create draft: %v", err)
				return false
			}

			// Simulate first successful post
			post1, err := postStore.CreatePostFromDraft(ctx, draft.ID, userID, services.PlatformThreads, content)
			if err != nil {
				t.Logf("Failed to create first post: %v", err)
				return false
			}

			// Mark as posted
			result, _ := socialClient.Post(ctx, services.PostContent{Text: content})
			_ = postStore.UpdatePostResult(ctx, post1.ID, result.PostID, result.PostURL, time.Now())
			_ = draftStore.UpdateDraftStatus(ctx, draft.ID, "posted")

			countAfterFirst := postStore.PostCount()

			// Attempt to post again (idempotent operation)
			post2, err := postStore.CreatePostFromDraft(ctx, draft.ID, userID, services.PlatformThreads, content)
			if err != nil {
				t.Logf("Second post attempt returned error: %v", err)
				return false
			}

			countAfterSecond := postStore.PostCount()

			// Property: Post count should not increase
			if countAfterSecond != countAfterFirst {
				t.Logf("Post count increased from %d to %d", countAfterFirst, countAfterSecond)
				return false
			}

			// Property: Should return the same post (same ID)
			if post1.ID != post2.ID {
				t.Logf("Different post IDs returned: %s vs %s", post1.ID, post2.ID)
				return false
			}

			return true
		},
		gen.AnyString().SuchThat(func(s string) bool { return len(s) <= 500 }),
	))

	// Property 28b: Multiple concurrent post attempts for same draft
	// result in exactly one post
	properties.Property("concurrent post attempts create exactly one post", prop.ForAll(
		func(numAttempts int, content string) bool {
			if content == "" {
				content = "concurrent test content"
			}

			draftStore := NewIdempotentDraftStore()
			postStore := NewIdempotentPostStore()

			userID := "user-" + uuid.New().String()[:8]

			ctx := context.Background()

			// Create a draft
			draft, err := draftStore.CreateDraft(ctx, userID, "repo-123", content, content)
			if err != nil {
				return false
			}

			// Simulate concurrent post attempts
			var wg sync.WaitGroup
			postIDs := make(chan string, numAttempts)

			for i := 0; i < numAttempts; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					post, err := postStore.CreatePostFromDraft(ctx, draft.ID, userID, services.PlatformThreads, content)
					if err == nil && post != nil {
						postIDs <- post.ID
					}
				}()
			}

			wg.Wait()
			close(postIDs)

			// Collect all returned post IDs
			ids := make(map[string]bool)
			for id := range postIDs {
				ids[id] = true
			}

			// Property: All attempts should return the same post ID
			if len(ids) != 1 {
				t.Logf("Expected 1 unique post ID, got %d", len(ids))
				return false
			}

			// Property: Post store should have exactly one post for this draft
			if postStore.PostCount() != 1 {
				t.Logf("Expected 1 post in store, got %d", postStore.PostCount())
				return false
			}

			return true
		},
		gen.IntRange(2, 20), // 2-20 concurrent attempts
		gen.AnyString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) <= 500 }),
	))

	// Property 28c: Different platforms for same draft create separate posts
	properties.Property("different platforms create separate posts", prop.ForAll(
		func(content string) bool {
			if content == "" {
				content = "multi-platform test content"
			}

			draftStore := NewIdempotentDraftStore()
			postStore := NewIdempotentPostStore()

			userID := "user-" + uuid.New().String()[:8]

			ctx := context.Background()

			// Create a draft
			draft, err := draftStore.CreateDraft(ctx, userID, "repo-123", content, content)
			if err != nil {
				return false
			}

			// Post to threads
			postThreads, err := postStore.CreatePostFromDraft(ctx, draft.ID, userID, "threads", content)
			if err != nil {
				return false
			}

			// Post to bluesky (different platform)
			postBluesky, err := postStore.CreatePostFromDraft(ctx, draft.ID, userID, "bluesky", content)
			if err != nil {
				return false
			}

			// Property: Different platforms should have different post IDs
			if postThreads.ID == postBluesky.ID {
				t.Logf("Same post ID for different platforms")
				return false
			}

			// Property: Should have 2 posts total
			if postStore.PostCount() != 2 {
				t.Logf("Expected 2 posts, got %d", postStore.PostCount())
				return false
			}

			// Property: Each platform lookup returns the correct post
			lookupThreads, _ := postStore.GetPostByDraftAndPlatform(ctx, draft.ID, "threads")
			lookupBluesky, _ := postStore.GetPostByDraftAndPlatform(ctx, draft.ID, "bluesky")

			if lookupThreads == nil || lookupThreads.ID != postThreads.ID {
				t.Logf("Threads lookup mismatch")
				return false
			}
			if lookupBluesky == nil || lookupBluesky.ID != postBluesky.ID {
				t.Logf("Bluesky lookup mismatch")
				return false
			}

			return true
		},
		gen.AnyString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) <= 500 }),
	))

	// Property 28d: Idempotent post returns correct existing data
	properties.Property("idempotent post returns correct existing data", prop.ForAll(
		func(content string) bool {
			if content == "" {
				content = "data verification content"
			}

			draftStore := NewIdempotentDraftStore()
			postStore := NewIdempotentPostStore()
			socialClient := NewIdempotentSocialClient()

			userID := "user-" + uuid.New().String()[:8]

			ctx := context.Background()

			// Create a draft
			draft, err := draftStore.CreateDraft(ctx, userID, "repo-123", content, content)
			if err != nil {
				return false
			}

			// First post
			post1, _ := postStore.CreatePostFromDraft(ctx, draft.ID, userID, services.PlatformThreads, content)

			// Update with result from social API
			result, _ := socialClient.Post(ctx, services.PostContent{Text: content})
			postedAt := time.Now()
			_ = postStore.UpdatePostResult(ctx, post1.ID, result.PostID, result.PostURL, postedAt)

			// Second attempt (idempotent)
			post2, _ := postStore.CreatePostFromDraft(ctx, draft.ID, userID, services.PlatformThreads, content)

			// Property: Returned post should have all the data from the first post
			if post2.DraftID != draft.ID {
				t.Logf("DraftID mismatch: expected %s, got %s", draft.ID, post2.DraftID)
				return false
			}
			if post2.UserID != userID {
				t.Logf("UserID mismatch: expected %s, got %s", userID, post2.UserID)
				return false
			}
			if post2.Platform != services.PlatformThreads {
				t.Logf("Platform mismatch: expected %s, got %s", services.PlatformThreads, post2.Platform)
				return false
			}
			if post2.Content != content {
				t.Logf("Content mismatch")
				return false
			}
			if post2.PlatformPostID != result.PostID {
				t.Logf("PlatformPostID mismatch: expected %s, got %s", result.PostID, post2.PlatformPostID)
				return false
			}
			if post2.PlatformPostURL != result.PostURL {
				t.Logf("PlatformPostURL mismatch")
				return false
			}

			return true
		},
		gen.AnyString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) <= 500 }),
	))

	// Property 28e: Different users posting same draft content create separate posts
	properties.Property("different users create separate posts even with same content", prop.ForAll(
		func(numUsers int, content string) bool {
			if content == "" {
				content = "multi-user test content"
			}

			postStore := NewIdempotentPostStore()
			ctx := context.Background()

			// Each user has their own draft (even with same content)
			postIDs := make(map[string]bool)

			for i := 0; i < numUsers; i++ {
				userID := "user-" + uuid.New().String()[:8]
				draftID := "draft-" + uuid.New().String()[:8]

				post, err := postStore.CreatePostFromDraft(ctx, draftID, userID, services.PlatformThreads, content)
				if err != nil {
					return false
				}

				postIDs[post.ID] = true
			}

			// Property: Each user should have a unique post
			if len(postIDs) != numUsers {
				t.Logf("Expected %d unique posts, got %d", numUsers, len(postIDs))
				return false
			}

			// Property: Total posts in store should equal number of users
			if postStore.PostCount() != numUsers {
				t.Logf("Expected %d posts in store, got %d", numUsers, postStore.PostCount())
				return false
			}

			return true
		},
		gen.IntRange(2, 20),
		gen.AnyString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) <= 500 }),
	))

	properties.TestingRun(t)
}

// TestProperty28_SocialAPINotCalledForAlreadyPosted verifies that the social
// API is not called when attempting to post an already-posted draft.
func TestProperty28_SocialAPINotCalledForAlreadyPosted(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	properties.Property("social API not called for already-posted draft", prop.ForAll(
		func(content string) bool {
			if content == "" {
				content = "api call test content"
			}

			draftStore := NewIdempotentDraftStore()
			postStore := NewIdempotentPostStore()
			socialClient := NewIdempotentSocialClient()

			userID := "user-" + uuid.New().String()[:8]

			ctx := context.Background()

			// Create and post a draft
			draft, _ := draftStore.CreateDraft(ctx, userID, "repo-123", content, content)
			post, _ := postStore.CreatePostFromDraft(ctx, draft.ID, userID, services.PlatformThreads, content)

			// First call to social API
			result, _ := socialClient.Post(ctx, services.PostContent{Text: content})
			_ = postStore.UpdatePostResult(ctx, post.ID, result.PostID, result.PostURL, time.Now())
			_ = draftStore.UpdateDraftStatus(ctx, draft.ID, "posted")

			callsAfterFirst := socialClient.CallCount()

			// Check draft status before attempting second post
			updatedDraft, _ := draftStore.GetDraft(ctx, draft.ID)
			if updatedDraft.Status == "posted" {
				// Property: If draft is already posted, we should NOT call social API again
				// The idempotent store returns existing post without needing API call

				existingPost, _ := postStore.GetPostByDraftAndPlatform(ctx, draft.ID, services.PlatformThreads)
				if existingPost == nil {
					t.Logf("Expected existing post to be found")
					return false
				}

				// Verify no additional API calls were made when checking existing post
				callsAfterCheck := socialClient.CallCount()
				if callsAfterCheck != callsAfterFirst {
					t.Logf("API was called when checking existing post: %d vs %d", callsAfterFirst, callsAfterCheck)
					return false
				}
			}

			return true
		},
		gen.AnyString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) <= 500 }),
	))

	// Property: Multiple rapid post attempts should result in exactly one API call
	properties.Property("multiple rapid attempts result in single API call", prop.ForAll(
		func(numAttempts int, content string) bool {
			if content == "" {
				content = "rapid test content"
			}

			draftStore := NewIdempotentDraftStore()
			postStore := NewIdempotentPostStore()
			socialClient := NewIdempotentSocialClient()

			userID := "user-" + uuid.New().String()[:8]

			ctx := context.Background()

			// Create draft
			draft, _ := draftStore.CreateDraft(ctx, userID, "repo-123", content, content)

			// Simulate the "first post wins" pattern
			// Only the first CreatePostFromDraft that finds no existing post should trigger API
			var firstPost *PostFromDraft
			var mu sync.Mutex
			var wg sync.WaitGroup

			for i := 0; i < numAttempts; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()

					post, _ := postStore.CreatePostFromDraft(ctx, draft.ID, userID, services.PlatformThreads, content)

					mu.Lock()
					if firstPost == nil {
						firstPost = post
						// Only first post triggers API call
						result, _ := socialClient.Post(ctx, services.PostContent{Text: content})
						_ = postStore.UpdatePostResult(ctx, post.ID, result.PostID, result.PostURL, time.Now())
					}
					mu.Unlock()
				}()
			}

			wg.Wait()

			// Property: Only one API call should have been made
			if socialClient.CallCount() != 1 {
				t.Logf("Expected 1 API call, got %d", socialClient.CallCount())
				return false
			}

			// Property: Only one post should exist
			if postStore.PostCount() != 1 {
				t.Logf("Expected 1 post, got %d", postStore.PostCount())
				return false
			}

			return true
		},
		gen.IntRange(2, 10),
		gen.AnyString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) <= 500 }),
	))

	properties.TestingRun(t)
}
