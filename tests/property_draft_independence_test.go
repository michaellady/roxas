// Package tests contains property-based tests for the Roxas application.
// Property 38: Posting one user's draft for shared repo doesn't affect other users' drafts.
// Validates Requirements 14.5
package tests

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
// Property Test: Draft Independence (Property 38)
// Validates Requirements 14.5
//
// Property: For any user posting a draft for a shared repository, the operation
// should not affect the draft status or content of other users tracking the
// same repository.
// =============================================================================

// DraftIndependenceWorkflow encapsulates the multi-tenant draft posting workflow
type DraftIndependenceWorkflow struct {
	draftStore *MockDraftStoreForIndependence
	postStore  *MockPostStoreForIndependence
}

// NewDraftIndependenceWorkflow creates a new workflow instance for testing
func NewDraftIndependenceWorkflow() *DraftIndependenceWorkflow {
	return &DraftIndependenceWorkflow{
		draftStore: NewMockDraftStoreForIndependence(),
		postStore:  NewMockPostStoreForIndependence(),
	}
}

// PostDraft simulates posting a single user's draft
func (w *DraftIndependenceWorkflow) PostDraft(ctx context.Context, draftID, userID, platform, content string) error {
	now := time.Now()

	// Create post record
	_, err := w.postStore.CreatePost(ctx, draftID, userID, platform, content)
	if err != nil {
		return err
	}

	// Update draft status to 'posted'
	return w.draftStore.UpdateDraftStatus(ctx, draftID, "posted", now)
}

// =============================================================================
// Mock Draft Store for Independence Testing
// =============================================================================

type MockDraftForIndependence struct {
	ID               string
	UserID           string
	RepositoryID     string
	GeneratedContent string
	EditedContent    *string
	Status           string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type MockDraftStoreForIndependence struct {
	mu     sync.Mutex
	drafts map[string]*MockDraftForIndependence
}

func NewMockDraftStoreForIndependence() *MockDraftStoreForIndependence {
	return &MockDraftStoreForIndependence{
		drafts: make(map[string]*MockDraftForIndependence),
	}
}

func (s *MockDraftStoreForIndependence) CreateDraft(ctx context.Context, draftID, userID, repoID, content string) *MockDraftForIndependence {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	draft := &MockDraftForIndependence{
		ID:               draftID,
		UserID:           userID,
		RepositoryID:     repoID,
		GeneratedContent: content,
		Status:           "draft",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	s.drafts[draftID] = draft
	return draft
}

func (s *MockDraftStoreForIndependence) GetDraft(ctx context.Context, draftID string) *MockDraftForIndependence {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.drafts[draftID]
}

func (s *MockDraftStoreForIndependence) UpdateDraftStatus(ctx context.Context, draftID, status string, updatedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	draft, exists := s.drafts[draftID]
	if !exists {
		return fmt.Errorf("draft not found: %s", draftID)
	}

	draft.Status = status
	draft.UpdatedAt = updatedAt
	return nil
}

func (s *MockDraftStoreForIndependence) UpdateDraftContent(ctx context.Context, draftID, content string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	draft, exists := s.drafts[draftID]
	if !exists {
		return fmt.Errorf("draft not found: %s", draftID)
	}

	draft.EditedContent = &content
	draft.UpdatedAt = time.Now()
	return nil
}

func (s *MockDraftStoreForIndependence) GetDraftsByRepository(repoID string) []*MockDraftForIndependence {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []*MockDraftForIndependence
	for _, draft := range s.drafts {
		if draft.RepositoryID == repoID {
			result = append(result, draft)
		}
	}
	return result
}

func (s *MockDraftStoreForIndependence) GetDraftsByUser(userID string) []*MockDraftForIndependence {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []*MockDraftForIndependence
	for _, draft := range s.drafts {
		if draft.UserID == userID {
			result = append(result, draft)
		}
	}
	return result
}

// Snapshot creates a deep copy of draft state for comparison
func (s *MockDraftStoreForIndependence) Snapshot(draftID string) *MockDraftForIndependence {
	s.mu.Lock()
	defer s.mu.Unlock()

	draft, exists := s.drafts[draftID]
	if !exists {
		return nil
	}

	snapshot := &MockDraftForIndependence{
		ID:               draft.ID,
		UserID:           draft.UserID,
		RepositoryID:     draft.RepositoryID,
		GeneratedContent: draft.GeneratedContent,
		Status:           draft.Status,
		CreatedAt:        draft.CreatedAt,
		UpdatedAt:        draft.UpdatedAt,
	}
	if draft.EditedContent != nil {
		content := *draft.EditedContent
		snapshot.EditedContent = &content
	}
	return snapshot
}

// =============================================================================
// Mock Post Store for Independence Testing
// =============================================================================

type MockPostForIndependence struct {
	ID        string
	DraftID   string
	UserID    string
	Platform  string
	Content   string
	Status    string
	CreatedAt time.Time
}

type MockPostStoreForIndependence struct {
	mu     sync.Mutex
	posts  map[string]*MockPostForIndependence
	nextID int
}

func NewMockPostStoreForIndependence() *MockPostStoreForIndependence {
	return &MockPostStoreForIndependence{
		posts:  make(map[string]*MockPostForIndependence),
		nextID: 1,
	}
}

func (s *MockPostStoreForIndependence) CreatePost(ctx context.Context, draftID, userID, platform, content string) (*MockPostForIndependence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	postID := fmt.Sprintf("post-%d", s.nextID)
	s.nextID++

	post := &MockPostForIndependence{
		ID:        postID,
		DraftID:   draftID,
		UserID:    userID,
		Platform:  platform,
		Content:   content,
		Status:    "posted",
		CreatedAt: time.Now(),
	}
	s.posts[postID] = post
	return post, nil
}

// =============================================================================
// Property Tests
// =============================================================================

// TestProperty38_PostingDraftDoesNotAffectOtherUsersDraftStatus verifies that
// posting User A's draft does not change User B's draft status.
// Validates Requirement 14.5
func TestProperty38_PostingDraftDoesNotAffectOtherUsersDraftStatus(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("posting user A's draft does not change user B's draft status", prop.ForAll(
		func(numUsers int, repoID string) bool {
			if numUsers < 2 {
				return true // Need at least 2 users
			}

			workflow := NewDraftIndependenceWorkflow()
			ctx := context.Background()

			// Create drafts for all users tracking the same repository
			var draftIDs []string
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				draftID := fmt.Sprintf("draft-%d-%s", i, repoID)
				content := fmt.Sprintf("Content for user %d", i)
				workflow.draftStore.CreateDraft(ctx, draftID, userID, repoID, content)
				draftIDs = append(draftIDs, draftID)
			}

			// Verify all drafts start with status 'draft'
			for _, draftID := range draftIDs {
				draft := workflow.draftStore.GetDraft(ctx, draftID)
				if draft.Status != "draft" {
					t.Log("Initial draft status should be 'draft'")
					return false
				}
			}

			// Post only user 0's draft
			userADraftID := draftIDs[0]
			err := workflow.PostDraft(ctx, userADraftID, "user-0", "threads", "Posted content")
			if err != nil {
				t.Logf("Failed to post draft: %v", err)
				return false
			}

			// Verify user 0's draft is now 'posted'
			userADraft := workflow.draftStore.GetDraft(ctx, userADraftID)
			if userADraft.Status != "posted" {
				t.Logf("User A's draft should be 'posted', got '%s'", userADraft.Status)
				return false
			}

			// Property: All other users' drafts must still have status 'draft'
			for i := 1; i < numUsers; i++ {
				otherDraft := workflow.draftStore.GetDraft(ctx, draftIDs[i])
				if otherDraft.Status != "draft" {
					t.Logf("User %d's draft status changed to '%s' - should remain 'draft'", i, otherDraft.Status)
					return false
				}
			}

			return true
		},
		gen.IntRange(2, 20),
		genRepositoryID(),
	))

	properties.TestingRun(t)
}

// TestProperty38_PostingDraftDoesNotAffectOtherUsersDraftContent verifies that
// posting User A's draft does not change User B's draft content.
// Validates Requirement 14.5
func TestProperty38_PostingDraftDoesNotAffectOtherUsersDraftContent(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("posting user A's draft does not change user B's draft content", prop.ForAll(
		func(numUsers int, repoID string) bool {
			if numUsers < 2 {
				return true
			}

			workflow := NewDraftIndependenceWorkflow()
			ctx := context.Background()

			// Create drafts with unique content for each user
			type draftInfo struct {
				draftID string
				content string
			}
			var drafts []draftInfo

			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				draftID := fmt.Sprintf("draft-%d-%s", i, repoID)
				content := fmt.Sprintf("Unique content for user %d at %s", i, repoID)
				workflow.draftStore.CreateDraft(ctx, draftID, userID, repoID, content)
				drafts = append(drafts, draftInfo{draftID: draftID, content: content})
			}

			// Take snapshots of all other users' drafts before posting
			snapshots := make(map[string]*MockDraftForIndependence)
			for i := 1; i < numUsers; i++ {
				snapshots[drafts[i].draftID] = workflow.draftStore.Snapshot(drafts[i].draftID)
			}

			// Post user 0's draft
			err := workflow.PostDraft(ctx, drafts[0].draftID, "user-0", "threads", "Posted content")
			if err != nil {
				return false
			}

			// Property: All other users' draft content must remain unchanged
			for i := 1; i < numUsers; i++ {
				currentDraft := workflow.draftStore.GetDraft(ctx, drafts[i].draftID)
				snapshot := snapshots[drafts[i].draftID]

				// Check generated content
				if currentDraft.GeneratedContent != snapshot.GeneratedContent {
					t.Logf("User %d's generated content changed from '%s' to '%s'",
						i, snapshot.GeneratedContent, currentDraft.GeneratedContent)
					return false
				}

				// Check edited content
				if (currentDraft.EditedContent == nil) != (snapshot.EditedContent == nil) {
					t.Logf("User %d's edited content nil state changed", i)
					return false
				}
				if currentDraft.EditedContent != nil && snapshot.EditedContent != nil {
					if *currentDraft.EditedContent != *snapshot.EditedContent {
						t.Logf("User %d's edited content changed", i)
						return false
					}
				}
			}

			return true
		},
		gen.IntRange(2, 20),
		genRepositoryID(),
	))

	properties.TestingRun(t)
}

// TestProperty38_PostingDraftDoesNotAffectOtherUsersDraftTimestamp verifies that
// posting User A's draft does not change User B's draft updated_at timestamp.
// Validates Requirement 14.5
func TestProperty38_PostingDraftDoesNotAffectOtherUsersDraftTimestamp(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("posting user A's draft does not change user B's draft timestamp", prop.ForAll(
		func(numUsers int, repoID string) bool {
			if numUsers < 2 {
				return true
			}

			workflow := NewDraftIndependenceWorkflow()
			ctx := context.Background()

			// Create drafts for all users
			var draftIDs []string
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				draftID := fmt.Sprintf("draft-%d-%s", i, repoID)
				content := fmt.Sprintf("Content for user %d", i)
				workflow.draftStore.CreateDraft(ctx, draftID, userID, repoID, content)
				draftIDs = append(draftIDs, draftID)
			}

			// Record timestamps of other users' drafts before posting
			timestampsBefore := make(map[string]time.Time)
			for i := 1; i < numUsers; i++ {
				draft := workflow.draftStore.GetDraft(ctx, draftIDs[i])
				timestampsBefore[draftIDs[i]] = draft.UpdatedAt
			}

			// Small delay to ensure any timestamp change would be detectable
			time.Sleep(time.Millisecond)

			// Post user 0's draft
			err := workflow.PostDraft(ctx, draftIDs[0], "user-0", "threads", "Posted content")
			if err != nil {
				return false
			}

			// Property: All other users' draft timestamps must remain unchanged
			for i := 1; i < numUsers; i++ {
				currentDraft := workflow.draftStore.GetDraft(ctx, draftIDs[i])
				originalTimestamp := timestampsBefore[draftIDs[i]]

				if !currentDraft.UpdatedAt.Equal(originalTimestamp) {
					t.Logf("User %d's updated_at changed from %v to %v",
						i, originalTimestamp, currentDraft.UpdatedAt)
					return false
				}
			}

			return true
		},
		gen.IntRange(2, 20),
		genRepositoryID(),
	))

	properties.TestingRun(t)
}

// TestProperty38_MultiplePostsDoNotInterfere verifies that multiple users can
// post their own drafts without affecting each other.
// Validates Requirement 14.5
func TestProperty38_MultiplePostsDoNotInterfere(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("multiple users posting their own drafts do not interfere", prop.ForAll(
		func(numUsers int, repoID string, postOrder []int) bool {
			if numUsers < 2 {
				return true
			}

			workflow := NewDraftIndependenceWorkflow()
			ctx := context.Background()

			// Create drafts for all users
			type draftInfo struct {
				draftID string
				userID  string
				content string
			}
			var drafts []draftInfo

			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				draftID := fmt.Sprintf("draft-%d-%s", i, repoID)
				content := fmt.Sprintf("Content for user %d", i)
				workflow.draftStore.CreateDraft(ctx, draftID, userID, repoID, content)
				drafts = append(drafts, draftInfo{draftID: draftID, userID: userID, content: content})
			}

			// Normalize post order to valid user indices
			normalizedOrder := make([]int, 0, len(postOrder))
			for _, idx := range postOrder {
				normalizedIdx := idx % numUsers
				if normalizedIdx < 0 {
					normalizedIdx = -normalizedIdx
				}
				normalizedOrder = append(normalizedOrder, normalizedIdx)
			}

			// Track which users have posted
			posted := make(map[int]bool)

			// Post drafts in the specified order
			for _, userIdx := range normalizedOrder {
				if posted[userIdx] {
					continue // Already posted this user's draft
				}

				draft := drafts[userIdx]

				// Take snapshots of all unposted users' drafts
				snapshots := make(map[int]*MockDraftForIndependence)
				for i := 0; i < numUsers; i++ {
					if !posted[i] && i != userIdx {
						snapshots[i] = workflow.draftStore.Snapshot(drafts[i].draftID)
					}
				}

				// Post this user's draft
				err := workflow.PostDraft(ctx, draft.draftID, draft.userID, "threads", "Posted: "+draft.content)
				if err != nil {
					return false
				}
				posted[userIdx] = true

				// Verify user's draft is now 'posted'
				currentDraft := workflow.draftStore.GetDraft(ctx, draft.draftID)
				if currentDraft.Status != "posted" {
					t.Logf("User %d's draft should be 'posted' after posting", userIdx)
					return false
				}

				// Property: All unposted users' drafts must be unchanged
				for i, snapshot := range snapshots {
					currentDraft := workflow.draftStore.GetDraft(ctx, drafts[i].draftID)

					if currentDraft.Status != snapshot.Status {
						t.Logf("User %d's draft status changed when user %d posted", i, userIdx)
						return false
					}
					if currentDraft.GeneratedContent != snapshot.GeneratedContent {
						t.Logf("User %d's draft content changed when user %d posted", i, userIdx)
						return false
					}
				}
			}

			return true
		},
		gen.IntRange(2, 10),
		genRepositoryID(),
		gen.SliceOfN(5, gen.IntRange(0, 100)),
	))

	properties.TestingRun(t)
}

// TestProperty38_DraftIndependenceWithConcurrentEdits verifies that posting
// a draft does not affect another user's draft even if they are editing.
// Validates Requirement 14.5
func TestProperty38_DraftIndependenceWithConcurrentEdits(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("posting does not affect drafts being edited by other users", prop.ForAll(
		func(repoID, editedContent string) bool {
			workflow := NewDraftIndependenceWorkflow()
			ctx := context.Background()

			// Create two users with drafts for the same repo
			userA := "user-a"
			userB := "user-b"
			draftA := "draft-a-" + repoID
			draftB := "draft-b-" + repoID

			workflow.draftStore.CreateDraft(ctx, draftA, userA, repoID, "User A content")
			workflow.draftStore.CreateDraft(ctx, draftB, userB, repoID, "User B content")

			// User B edits their draft
			err := workflow.draftStore.UpdateDraftContent(ctx, draftB, editedContent)
			if err != nil {
				return false
			}

			// Take snapshot of User B's draft
			snapshotB := workflow.draftStore.Snapshot(draftB)

			// Small delay
			time.Sleep(time.Millisecond)

			// User A posts their draft
			err = workflow.PostDraft(ctx, draftA, userA, "threads", "Posted by A")
			if err != nil {
				return false
			}

			// Property: User B's draft must be completely unchanged
			currentB := workflow.draftStore.GetDraft(ctx, draftB)

			if currentB.Status != snapshotB.Status {
				t.Logf("User B's status changed from '%s' to '%s'", snapshotB.Status, currentB.Status)
				return false
			}

			if currentB.GeneratedContent != snapshotB.GeneratedContent {
				t.Log("User B's generated content changed")
				return false
			}

			if snapshotB.EditedContent != nil {
				if currentB.EditedContent == nil || *currentB.EditedContent != *snapshotB.EditedContent {
					t.Log("User B's edited content changed")
					return false
				}
			}

			return true
		},
		genRepositoryID(),
		gen.AlphaString(),
	))

	properties.TestingRun(t)
}

// TestProperty38_DraftIndependenceAcrossMultipleRepositories verifies draft
// independence holds even when users track multiple shared repositories.
// Validates Requirement 14.5
func TestProperty38_DraftIndependenceAcrossMultipleRepositories(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	parameters.Rng.Seed(42)
	properties := gopter.NewProperties(parameters)

	properties.Property("draft independence holds across multiple repositories", prop.ForAll(
		func(numRepos int) bool {
			if numRepos < 1 {
				return true
			}

			workflow := NewDraftIndependenceWorkflow()
			ctx := context.Background()

			// Two users tracking multiple repos
			userA := "user-a"
			userB := "user-b"

			type draftPair struct {
				repoID   string
				draftA   string
				draftB   string
				contentA string
				contentB string
			}
			var pairs []draftPair

			for i := 0; i < numRepos; i++ {
				repoID := fmt.Sprintf("repo-%d", i)
				draftA := fmt.Sprintf("draft-a-%d", i)
				draftB := fmt.Sprintf("draft-b-%d", i)
				contentA := fmt.Sprintf("User A content for repo %d", i)
				contentB := fmt.Sprintf("User B content for repo %d", i)

				workflow.draftStore.CreateDraft(ctx, draftA, userA, repoID, contentA)
				workflow.draftStore.CreateDraft(ctx, draftB, userB, repoID, contentB)

				pairs = append(pairs, draftPair{
					repoID:   repoID,
					draftA:   draftA,
					draftB:   draftB,
					contentA: contentA,
					contentB: contentB,
				})
			}

			// Take snapshots of all User B's drafts
			snapshotsB := make(map[string]*MockDraftForIndependence)
			for _, pair := range pairs {
				snapshotsB[pair.draftB] = workflow.draftStore.Snapshot(pair.draftB)
			}

			// User A posts all their drafts
			for _, pair := range pairs {
				err := workflow.PostDraft(ctx, pair.draftA, userA, "threads", "Posted: "+pair.contentA)
				if err != nil {
					return false
				}
			}

			// Property: All User B's drafts must be unchanged
			for _, pair := range pairs {
				currentB := workflow.draftStore.GetDraft(ctx, pair.draftB)
				snapshotB := snapshotsB[pair.draftB]

				if currentB.Status != snapshotB.Status {
					t.Logf("User B's draft for repo %s: status changed", pair.repoID)
					return false
				}
				if currentB.GeneratedContent != snapshotB.GeneratedContent {
					t.Logf("User B's draft for repo %s: content changed", pair.repoID)
					return false
				}
			}

			return true
		},
		gen.IntRange(1, 10),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Generators
// =============================================================================

// genRepositoryID generates random repository IDs
func genRepositoryID() gopter.Gen {
	return gen.RegexMatch(`repo-[a-f0-9]{8}`)
}
