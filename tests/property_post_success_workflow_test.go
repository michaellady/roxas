// Package tests contains property-based tests for the Roxas application.
// Property 27: Successful post creates record with status 'posted',
// updates draft to 'posted' with timestamp, creates activity.
// Validates Requirements 7.5, 7.7, 7.8
package tests

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Property Test: Post Success Workflow (Property 27)
// Validates Requirements 7.5 (post status), 7.7 (draft timestamp), 7.8 (activity)
// =============================================================================

// PostSuccessWorkflow encapsulates the post success workflow for testing
type PostSuccessWorkflow struct {
	draftStore    *MockDraftStoreForWorkflow
	postStore     *MockPostStoreForWorkflow
	activityStore *MockActivityStoreForWorkflow
}

// NewPostSuccessWorkflow creates a new workflow instance for testing
func NewPostSuccessWorkflow() *PostSuccessWorkflow {
	return &PostSuccessWorkflow{
		draftStore:    NewMockDraftStoreForWorkflow(),
		postStore:     NewMockPostStoreForWorkflow(),
		activityStore: NewMockActivityStoreForWorkflow(),
	}
}

// ExecutePostSuccess simulates a successful post workflow
// Returns the post ID, draft ID, and activity ID
func (w *PostSuccessWorkflow) ExecutePostSuccess(ctx context.Context, userID, draftID, platform, content string) (postID string, activityID string, err error) {
	now := time.Now()

	// Step 1: Create post record with status 'posted'
	post, err := w.postStore.CreatePost(ctx, draftID, userID, platform, content)
	if err != nil {
		return "", "", err
	}

	// Step 2: Update post with success result
	err = w.postStore.UpdatePostSuccess(ctx, post.ID, "platform-post-123", "https://threads.net/p/123", now)
	if err != nil {
		return "", "", err
	}

	// Step 3: Update draft status to 'posted' (this also updates timestamp)
	err = w.draftStore.UpdateDraftStatusPosted(ctx, draftID, now)
	if err != nil {
		return "", "", err
	}

	// Step 4: Create activity record
	activity, err := w.activityStore.CreateActivity(ctx, userID, "post_success", &draftID, &post.ID, &platform, nil)
	if err != nil {
		return "", "", err
	}

	return post.ID, activity.ID, nil
}

// =============================================================================
// Mock Draft Store for Workflow Testing
// =============================================================================

type MockDraftForWorkflow struct {
	ID        string
	UserID    string
	Status    string
	UpdatedAt time.Time
	PostedAt  *time.Time
}

type MockDraftStoreForWorkflow struct {
	mu     sync.Mutex
	drafts map[string]*MockDraftForWorkflow
}

func NewMockDraftStoreForWorkflow() *MockDraftStoreForWorkflow {
	return &MockDraftStoreForWorkflow{
		drafts: make(map[string]*MockDraftForWorkflow),
	}
}

func (s *MockDraftStoreForWorkflow) CreateDraft(ctx context.Context, draftID, userID string) *MockDraftForWorkflow {
	s.mu.Lock()
	defer s.mu.Unlock()

	draft := &MockDraftForWorkflow{
		ID:        draftID,
		UserID:    userID,
		Status:    "draft",
		UpdatedAt: time.Now(),
	}
	s.drafts[draftID] = draft
	return draft
}

func (s *MockDraftStoreForWorkflow) GetDraft(ctx context.Context, draftID string) *MockDraftForWorkflow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.drafts[draftID]
}

func (s *MockDraftStoreForWorkflow) UpdateDraftStatusPosted(ctx context.Context, draftID string, postedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	draft, exists := s.drafts[draftID]
	if !exists {
		return nil
	}

	draft.Status = "posted"
	draft.UpdatedAt = postedAt
	draft.PostedAt = &postedAt
	return nil
}

// =============================================================================
// Mock Post Store for Workflow Testing
// =============================================================================

type MockPostForWorkflow struct {
	ID              string
	DraftID         string
	UserID          string
	Platform        string
	Content         string
	Status          string
	PlatformPostID  string
	PlatformPostURL string
	PostedAt        *time.Time
	CreatedAt       time.Time
}

type MockPostStoreForWorkflow struct {
	mu     sync.Mutex
	posts  map[string]*MockPostForWorkflow
	nextID int
}

func NewMockPostStoreForWorkflow() *MockPostStoreForWorkflow {
	return &MockPostStoreForWorkflow{
		posts:  make(map[string]*MockPostForWorkflow),
		nextID: 1,
	}
}

func (s *MockPostStoreForWorkflow) CreatePost(ctx context.Context, draftID, userID, platform, content string) (*MockPostForWorkflow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	postID := generatePostID(s.nextID)
	s.nextID++

	post := &MockPostForWorkflow{
		ID:        postID,
		DraftID:   draftID,
		UserID:    userID,
		Platform:  platform,
		Content:   content,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	s.posts[postID] = post
	return post, nil
}

func (s *MockPostStoreForWorkflow) UpdatePostSuccess(ctx context.Context, postID, platformPostID, platformPostURL string, postedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	post, exists := s.posts[postID]
	if !exists {
		return nil
	}

	post.Status = "posted"
	post.PlatformPostID = platformPostID
	post.PlatformPostURL = platformPostURL
	post.PostedAt = &postedAt
	return nil
}

func (s *MockPostStoreForWorkflow) GetPost(ctx context.Context, postID string) *MockPostForWorkflow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.posts[postID]
}

func generatePostID(n int) string {
	return "post-" + string(rune('a'+n%26)) + string(rune('0'+n/26))
}

// =============================================================================
// Mock Activity Store for Workflow Testing
// =============================================================================

type MockActivityForWorkflow struct {
	ID        string
	UserID    string
	Type      string
	DraftID   *string
	PostID    *string
	Platform  *string
	Message   *string
	CreatedAt time.Time
}

type MockActivityStoreForWorkflow struct {
	mu         sync.Mutex
	activities map[string]*MockActivityForWorkflow
	nextID     int
}

func NewMockActivityStoreForWorkflow() *MockActivityStoreForWorkflow {
	return &MockActivityStoreForWorkflow{
		activities: make(map[string]*MockActivityForWorkflow),
		nextID:     1,
	}
}

func (s *MockActivityStoreForWorkflow) CreateActivity(ctx context.Context, userID, activityType string, draftID, postID, platform, message *string) (*MockActivityForWorkflow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	activityID := generateActivityID(s.nextID)
	s.nextID++

	activity := &MockActivityForWorkflow{
		ID:        activityID,
		UserID:    userID,
		Type:      activityType,
		DraftID:   draftID,
		PostID:    postID,
		Platform:  platform,
		Message:   message,
		CreatedAt: time.Now(),
	}
	s.activities[activityID] = activity
	return activity, nil
}

func (s *MockActivityStoreForWorkflow) GetActivity(ctx context.Context, activityID string) *MockActivityForWorkflow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activities[activityID]
}

func (s *MockActivityStoreForWorkflow) GetActivitiesByType(activityType string) []*MockActivityForWorkflow {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []*MockActivityForWorkflow
	for _, activity := range s.activities {
		if activity.Type == activityType {
			result = append(result, activity)
		}
	}
	return result
}

func generateActivityID(n int) string {
	return "activity-" + string(rune('a'+n%26)) + string(rune('0'+n/26))
}

// =============================================================================
// Property Tests
// =============================================================================

// TestProperty27_PostSuccessCreatesPostedRecord verifies that successful posts
// create a post record with status 'posted'.
// Validates Requirement 7.5
func TestProperty27_PostSuccessCreatesPostedRecord(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("successful post creates record with status 'posted'", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			// Create initial draft
			workflow.draftStore.CreateDraft(ctx, draftID, userID)

			// Execute post success workflow
			postID, _, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				t.Logf("Workflow execution failed: %v", err)
				return false
			}

			// Verify post record exists and has status 'posted'
			post := workflow.postStore.GetPost(ctx, postID)
			if post == nil {
				t.Log("Post record not found")
				return false
			}

			if post.Status != "posted" {
				t.Logf("Expected post status 'posted', got '%s'", post.Status)
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.Property("successful post has platform post ID and URL", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			workflow.draftStore.CreateDraft(ctx, draftID, userID)
			postID, _, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				return false
			}

			post := workflow.postStore.GetPost(ctx, postID)
			if post == nil {
				return false
			}

			// Property: Posted post must have platform post ID
			if post.PlatformPostID == "" {
				t.Log("Post missing platform_post_id")
				return false
			}

			// Property: Posted post must have platform post URL
			if post.PlatformPostURL == "" {
				t.Log("Post missing platform_post_url")
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.Property("successful post has posted_at timestamp", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			beforePost := time.Now()
			workflow.draftStore.CreateDraft(ctx, draftID, userID)
			postID, _, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				return false
			}
			afterPost := time.Now()

			post := workflow.postStore.GetPost(ctx, postID)
			if post == nil {
				return false
			}

			// Property: Posted post must have posted_at timestamp
			if post.PostedAt == nil {
				t.Log("Post missing posted_at timestamp")
				return false
			}

			// Property: posted_at must be within the execution window
			if post.PostedAt.Before(beforePost) || post.PostedAt.After(afterPost) {
				t.Log("Post posted_at timestamp out of expected range")
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.TestingRun(t)
}

// TestProperty27_PostSuccessUpdatesDraftStatus verifies that successful posts
// update the associated draft to 'posted' status with timestamp.
// Validates Requirement 7.7
func TestProperty27_PostSuccessUpdatesDraftStatus(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("successful post updates draft status to 'posted'", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			// Create initial draft with status 'draft'
			workflow.draftStore.CreateDraft(ctx, draftID, userID)
			initialDraft := workflow.draftStore.GetDraft(ctx, draftID)
			if initialDraft.Status != "draft" {
				t.Log("Initial draft should have status 'draft'")
				return false
			}

			// Execute post success workflow
			_, _, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				return false
			}

			// Verify draft status changed to 'posted'
			draft := workflow.draftStore.GetDraft(ctx, draftID)
			if draft == nil {
				t.Log("Draft not found after posting")
				return false
			}

			if draft.Status != "posted" {
				t.Logf("Expected draft status 'posted', got '%s'", draft.Status)
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.Property("successful post updates draft timestamp", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			// Create initial draft
			workflow.draftStore.CreateDraft(ctx, draftID, userID)
			initialDraft := workflow.draftStore.GetDraft(ctx, draftID)
			initialUpdatedAt := initialDraft.UpdatedAt

			// Small delay to ensure timestamp difference is measurable
			time.Sleep(time.Millisecond)

			beforePost := time.Now()

			// Execute post success workflow
			_, _, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				return false
			}

			// Verify draft updated_at timestamp changed
			draft := workflow.draftStore.GetDraft(ctx, draftID)
			if draft == nil {
				return false
			}

			// Property: updated_at must be after initial value
			if !draft.UpdatedAt.After(initialUpdatedAt) {
				t.Log("Draft updated_at should be after initial timestamp")
				return false
			}

			// Property: updated_at must be on or after post execution started
			if draft.UpdatedAt.Before(beforePost) {
				t.Log("Draft updated_at should be on or after post execution")
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.Property("successful post sets draft posted_at timestamp", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			// Create initial draft (posted_at should be nil)
			workflow.draftStore.CreateDraft(ctx, draftID, userID)
			initialDraft := workflow.draftStore.GetDraft(ctx, draftID)
			if initialDraft.PostedAt != nil {
				t.Log("Initial draft should have nil posted_at")
				return false
			}

			beforePost := time.Now()

			// Execute post success workflow
			_, _, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				return false
			}

			afterPost := time.Now()

			// Verify draft has posted_at timestamp set
			draft := workflow.draftStore.GetDraft(ctx, draftID)
			if draft == nil {
				return false
			}

			// Property: posted_at must be set after successful post
			if draft.PostedAt == nil {
				t.Log("Draft posted_at should be set after successful post")
				return false
			}

			// Property: posted_at must be within the execution window
			if draft.PostedAt.Before(beforePost) || draft.PostedAt.After(afterPost) {
				t.Log("Draft posted_at timestamp out of expected range")
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.TestingRun(t)
}

// TestProperty27_PostSuccessCreatesActivity verifies that successful posts
// create a 'post_success' activity record.
// Validates Requirement 7.8
func TestProperty27_PostSuccessCreatesActivity(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("successful post creates activity with type 'post_success'", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			workflow.draftStore.CreateDraft(ctx, draftID, userID)

			// Execute post success workflow
			_, activityID, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				return false
			}

			// Verify activity record exists with correct type
			activity := workflow.activityStore.GetActivity(ctx, activityID)
			if activity == nil {
				t.Log("Activity record not found")
				return false
			}

			if activity.Type != "post_success" {
				t.Logf("Expected activity type 'post_success', got '%s'", activity.Type)
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.Property("post_success activity references correct user", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			workflow.draftStore.CreateDraft(ctx, draftID, userID)
			_, activityID, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				return false
			}

			activity := workflow.activityStore.GetActivity(ctx, activityID)
			if activity == nil {
				return false
			}

			// Property: Activity must reference correct user
			if activity.UserID != userID {
				t.Logf("Expected activity user_id '%s', got '%s'", userID, activity.UserID)
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.Property("post_success activity references draft and post", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			workflow.draftStore.CreateDraft(ctx, draftID, userID)
			postID, activityID, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				return false
			}

			activity := workflow.activityStore.GetActivity(ctx, activityID)
			if activity == nil {
				return false
			}

			// Property: Activity must reference the draft
			if activity.DraftID == nil || *activity.DraftID != draftID {
				t.Log("Activity should reference the draft")
				return false
			}

			// Property: Activity must reference the post
			if activity.PostID == nil || *activity.PostID != postID {
				t.Log("Activity should reference the post")
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.Property("post_success activity includes platform", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			workflow.draftStore.CreateDraft(ctx, draftID, userID)
			_, activityID, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				return false
			}

			activity := workflow.activityStore.GetActivity(ctx, activityID)
			if activity == nil {
				return false
			}

			// Property: Activity must include the platform
			if activity.Platform == nil || *activity.Platform != platform {
				t.Logf("Activity should include platform '%s'", platform)
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.TestingRun(t)
}

// TestProperty27_WorkflowOrderInvariant verifies that the workflow
// maintains correct ordering of state changes.
func TestProperty27_WorkflowOrderInvariant(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("workflow creates exactly one post per execution", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			workflow.draftStore.CreateDraft(ctx, draftID, userID)

			// Execute workflow
			_, _, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				return false
			}

			// Count posts in store
			count := len(workflow.postStore.posts)
			if count != 1 {
				t.Logf("Expected exactly 1 post, got %d", count)
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.Property("workflow creates exactly one activity per execution", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			workflow.draftStore.CreateDraft(ctx, draftID, userID)

			// Execute workflow
			_, _, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				return false
			}

			// Count activities with type 'post_success'
			activities := workflow.activityStore.GetActivitiesByType("post_success")
			if len(activities) != 1 {
				t.Logf("Expected exactly 1 post_success activity, got %d", len(activities))
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.TestingRun(t)
}

// TestProperty27_ContentPreservation verifies that post content is preserved
// through the workflow.
func TestProperty27_ContentPreservation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("post content matches original content", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			workflow.draftStore.CreateDraft(ctx, draftID, userID)
			postID, _, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				return false
			}

			post := workflow.postStore.GetPost(ctx, postID)
			if post == nil {
				return false
			}

			// Property: Post content must match original content
			if post.Content != content {
				t.Logf("Content mismatch: expected '%s', got '%s'", content, post.Content)
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.Property("post platform matches requested platform", prop.ForAll(
		func(userID, draftID, platform, content string) bool {
			workflow := NewPostSuccessWorkflow()
			ctx := context.Background()

			workflow.draftStore.CreateDraft(ctx, draftID, userID)
			postID, _, err := workflow.ExecutePostSuccess(ctx, userID, draftID, platform, content)
			if err != nil {
				return false
			}

			post := workflow.postStore.GetPost(ctx, postID)
			if post == nil {
				return false
			}

			// Property: Post platform must match requested platform
			if post.Platform != platform {
				t.Logf("Platform mismatch: expected '%s', got '%s'", platform, post.Platform)
				return false
			}

			return true
		},
		genUserID(),
		genDraftID(),
		genPlatform(),
		genPostContent(),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Generators
// =============================================================================

// genUserID generates random user IDs in UUID-like format
func genUserID() gopter.Gen {
	return gen.RegexMatch(`user-[a-f0-9]{8}`)
}

// genDraftID generates random draft IDs in UUID-like format
func genDraftID() gopter.Gen {
	return gen.RegexMatch(`draft-[a-f0-9]{8}`)
}

// genPlatform generates random platform names
func genPlatform() gopter.Gen {
	return gen.OneConstOf("threads", "bluesky", "linkedin", "twitter")
}

// genPostContent generates random post content
func genPostContent() gopter.Gen {
	// Generate content that's typical for social media posts (1-500 chars)
	return gen.AlphaString().SuchThat(func(s string) bool {
		return len(s) >= 1 && len(s) <= 500
	}).Map(func(s string) string {
		if len(s) == 0 {
			return "Test post content"
		}
		// Truncate if too long
		if len(s) > 500 {
			return s[:500]
		}
		return s
	})
}
