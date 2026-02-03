// Package tests contains property-based tests for the Roxas application.
// Property 37: Fetching drafts/activity returns only records matching authenticated user_id.
// Validates Requirements 14.3, 14.4 (user data isolation, no cross-user data leakage)
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
// Property Test: User Data Isolation (Property 37)
// Validates Requirements 14.3, 14.4 (multi-tenant data isolation)
// =============================================================================

// IsolationDraft represents a draft for isolation testing
type IsolationDraft struct {
	ID           string
	UserID       string
	RepositoryID string
	Ref          string
	Status       string
	CreatedAt    time.Time
}

// IsolationActivity represents an activity for isolation testing
type IsolationActivity struct {
	ID        string
	UserID    string
	Type      string
	DraftID   *string
	CreatedAt time.Time
}

// IsolationDraftStore is a multi-tenant mock draft store for isolation testing
type IsolationDraftStore struct {
	mu     sync.Mutex
	drafts map[string]*IsolationDraft // draftID -> draft
	nextID int
}

// NewIsolationDraftStore creates a new multi-tenant draft store
func NewIsolationDraftStore() *IsolationDraftStore {
	return &IsolationDraftStore{
		drafts: make(map[string]*IsolationDraft),
		nextID: 1,
	}
}

// CreateDraft creates a new draft for a user
func (s *IsolationDraftStore) CreateDraft(ctx context.Context, userID, repoID, ref string) (*IsolationDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	draft := &IsolationDraft{
		ID:           fmt.Sprintf("draft-%d", s.nextID),
		UserID:       userID,
		RepositoryID: repoID,
		Ref:          ref,
		Status:       "draft",
		CreatedAt:    time.Now(),
	}
	s.nextID++
	s.drafts[draft.ID] = draft
	return draft, nil
}

// ListDraftsByUser retrieves all drafts for a specific user
// This mirrors the behavior of DraftStore.ListDraftsByUser
func (s *IsolationDraftStore) ListDraftsByUser(ctx context.Context, userID string) ([]*IsolationDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []*IsolationDraft
	for _, draft := range s.drafts {
		if draft.UserID == userID {
			result = append(result, draft)
		}
	}
	return result, nil
}

// GetAllDrafts returns all drafts in the store (for verification)
func (s *IsolationDraftStore) GetAllDrafts() []*IsolationDraft {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]*IsolationDraft, 0, len(s.drafts))
	for _, draft := range s.drafts {
		result = append(result, draft)
	}
	return result
}

// IsolationActivityStore is a multi-tenant mock activity store for isolation testing
type IsolationActivityStore struct {
	mu         sync.Mutex
	activities map[string]*IsolationActivity // activityID -> activity
	nextID     int
}

// NewIsolationActivityStore creates a new multi-tenant activity store
func NewIsolationActivityStore() *IsolationActivityStore {
	return &IsolationActivityStore{
		activities: make(map[string]*IsolationActivity),
		nextID:     1,
	}
}

// CreateActivity creates a new activity for a user
func (s *IsolationActivityStore) CreateActivity(ctx context.Context, userID, activityType string, draftID *string) (*IsolationActivity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	activity := &IsolationActivity{
		ID:        fmt.Sprintf("activity-%d", s.nextID),
		UserID:    userID,
		Type:      activityType,
		DraftID:   draftID,
		CreatedAt: time.Now(),
	}
	s.nextID++
	s.activities[activity.ID] = activity
	return activity, nil
}

// ListActivitiesByUser retrieves all activities for a specific user
// This mirrors the behavior of ActivityStore.ListActivitiesByUser
func (s *IsolationActivityStore) ListActivitiesByUser(ctx context.Context, userID string, limit, offset int) ([]*IsolationActivity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []*IsolationActivity
	for _, activity := range s.activities {
		if activity.UserID == userID {
			result = append(result, activity)
		}
	}

	// Apply pagination
	if offset > len(result) {
		return []*IsolationActivity{}, nil
	}
	result = result[offset:]
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}

	return result, nil
}

// GetAllActivities returns all activities in the store (for verification)
func (s *IsolationActivityStore) GetAllActivities() []*IsolationActivity {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]*IsolationActivity, 0, len(s.activities))
	for _, activity := range s.activities {
		result = append(result, activity)
	}
	return result
}

// =============================================================================
// Property Tests: Draft Isolation
// =============================================================================

// TestProperty37_DraftIsolation_OnlyReturnsMatchingUser verifies that
// ListDraftsByUser only returns drafts belonging to the requested user.
// Validates Requirement 14.3
func TestProperty37_DraftIsolation_OnlyReturnsMatchingUser(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(37)
	properties := gopter.NewProperties(parameters)

	// Generator for number of users (2-10)
	numUsersGen := gen.IntRange(2, 10)

	// Generator for number of drafts per user (1-5)
	draftsPerUserGen := gen.IntRange(1, 5)

	properties.Property("ListDraftsByUser returns only drafts belonging to requested user", prop.ForAll(
		func(numUsers, draftsPerUser int) bool {
			draftStore := NewIsolationDraftStore()
			ctx := context.Background()

			// Create drafts for multiple users
			userDraftCounts := make(map[string]int)
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				for j := 0; j < draftsPerUser; j++ {
					repoID := fmt.Sprintf("repo-%d-%d", i, j)
					ref := fmt.Sprintf("refs/heads/branch-%d", j)
					_, err := draftStore.CreateDraft(ctx, userID, repoID, ref)
					if err != nil {
						t.Logf("Failed to create draft: %v", err)
						return false
					}
					userDraftCounts[userID]++
				}
			}

			// Verify isolation for each user
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				drafts, err := draftStore.ListDraftsByUser(ctx, userID)
				if err != nil {
					t.Logf("Failed to list drafts: %v", err)
					return false
				}

				// Property: Every returned draft must belong to the requested user
				for _, draft := range drafts {
					if draft.UserID != userID {
						t.Logf("Draft %s has UserID %s, expected %s", draft.ID, draft.UserID, userID)
						return false
					}
				}

				// Property: Count must match expected
				if len(drafts) != userDraftCounts[userID] {
					t.Logf("User %s has %d drafts, expected %d", userID, len(drafts), userDraftCounts[userID])
					return false
				}
			}

			return true
		},
		numUsersGen,
		draftsPerUserGen,
	))

	properties.TestingRun(t)
}

// TestProperty37_DraftIsolation_NoCrossUserLeakage verifies that a user
// cannot see other users' drafts.
// Validates Requirement 14.4
func TestProperty37_DraftIsolation_NoCrossUserLeakage(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(37)
	properties := gopter.NewProperties(parameters)

	// Generator for number of users (2-20)
	numUsersGen := gen.IntRange(2, 20)

	// Generator for drafts per user (varying per user via additional generation)
	draftsGen := gen.IntRange(0, 10)

	properties.Property("user A cannot see user B's drafts through ListDraftsByUser", prop.ForAll(
		func(numUsers int, draftsPerUserBase int) bool {
			draftStore := NewIsolationDraftStore()
			ctx := context.Background()

			// Create drafts for each user with varying counts
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				// Vary draft count per user
				numDrafts := (draftsPerUserBase + i) % 10
				if numDrafts == 0 {
					numDrafts = 1
				}
				for j := 0; j < numDrafts; j++ {
					draftStore.CreateDraft(ctx, userID, fmt.Sprintf("repo-%d-%d", i, j), "refs/heads/main")
				}
			}

			totalDrafts := len(draftStore.GetAllDrafts())

			// For each user, verify they only see their own drafts
			sumOfUserDrafts := 0
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				drafts, _ := draftStore.ListDraftsByUser(ctx, userID)
				sumOfUserDrafts += len(drafts)

				// Property: No draft from another user should appear
				for _, draft := range drafts {
					if draft.UserID != userID {
						t.Logf("ISOLATION VIOLATION: User %s can see draft %s belonging to user %s",
							userID, draft.ID, draft.UserID)
						return false
					}
				}
			}

			// Property: Sum of all user-specific drafts must equal total drafts
			// (no duplicates, no missing drafts)
			if sumOfUserDrafts != totalDrafts {
				t.Logf("Sum of user drafts (%d) != total drafts (%d)", sumOfUserDrafts, totalDrafts)
				return false
			}

			return true
		},
		numUsersGen,
		draftsGen,
	))

	properties.TestingRun(t)
}

// TestProperty37_DraftIsolation_NonexistentUserReturnsEmpty verifies that
// querying for a non-existent user returns empty results.
// Validates Requirement 14.3
func TestProperty37_DraftIsolation_NonexistentUserReturnsEmpty(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(37)
	properties := gopter.NewProperties(parameters)

	properties.Property("ListDraftsByUser returns empty for non-existent user", prop.ForAll(
		func(numDrafts int) bool {
			draftStore := NewIsolationDraftStore()
			ctx := context.Background()

			// Create drafts for various users
			for i := 0; i < numDrafts; i++ {
				userID := fmt.Sprintf("user-%d", i)
				draftStore.CreateDraft(ctx, userID, fmt.Sprintf("repo-%d", i), "refs/heads/main")
			}

			// Query for a user that doesn't exist
			nonexistentUserID := "user-nonexistent-99999"
			drafts, err := draftStore.ListDraftsByUser(ctx, nonexistentUserID)
			if err != nil {
				t.Logf("Unexpected error: %v", err)
				return false
			}

			// Property: Must return empty slice for non-existent user
			if len(drafts) != 0 {
				t.Logf("Expected 0 drafts for non-existent user, got %d", len(drafts))
				return false
			}

			return true
		},
		gen.IntRange(1, 20),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Property Tests: Activity Isolation
// =============================================================================

// TestProperty37_ActivityIsolation_OnlyReturnsMatchingUser verifies that
// ListActivitiesByUser only returns activities belonging to the requested user.
// Validates Requirement 14.3
func TestProperty37_ActivityIsolation_OnlyReturnsMatchingUser(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(37)
	properties := gopter.NewProperties(parameters)

	// Generator for number of users (2-10)
	numUsersGen := gen.IntRange(2, 10)

	// Generator for number of activities per user (1-5)
	activitiesPerUserGen := gen.IntRange(1, 5)

	properties.Property("ListActivitiesByUser returns only activities belonging to requested user", prop.ForAll(
		func(numUsers, activitiesPerUser int) bool {
			activityStore := NewIsolationActivityStore()
			ctx := context.Background()

			// Create activities for multiple users
			userActivityCounts := make(map[string]int)
			activityTypes := []string{"draft_created", "post_success", "post_failed"}

			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				for j := 0; j < activitiesPerUser; j++ {
					activityType := activityTypes[j%len(activityTypes)]
					_, err := activityStore.CreateActivity(ctx, userID, activityType, nil)
					if err != nil {
						t.Logf("Failed to create activity: %v", err)
						return false
					}
					userActivityCounts[userID]++
				}
			}

			// Verify isolation for each user
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				activities, err := activityStore.ListActivitiesByUser(ctx, userID, 100, 0)
				if err != nil {
					t.Logf("Failed to list activities: %v", err)
					return false
				}

				// Property: Every returned activity must belong to the requested user
				for _, activity := range activities {
					if activity.UserID != userID {
						t.Logf("Activity %s has UserID %s, expected %s", activity.ID, activity.UserID, userID)
						return false
					}
				}

				// Property: Count must match expected
				if len(activities) != userActivityCounts[userID] {
					t.Logf("User %s has %d activities, expected %d", userID, len(activities), userActivityCounts[userID])
					return false
				}
			}

			return true
		},
		numUsersGen,
		activitiesPerUserGen,
	))

	properties.TestingRun(t)
}

// TestProperty37_ActivityIsolation_NoCrossUserLeakage verifies that a user
// cannot see other users' activities.
// Validates Requirement 14.4
func TestProperty37_ActivityIsolation_NoCrossUserLeakage(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(37)
	properties := gopter.NewProperties(parameters)

	// Generator for number of users (2-20)
	numUsersGen := gen.IntRange(2, 20)

	// Generator for activities per user (varying per user via additional generation)
	activitiesGen := gen.IntRange(0, 10)

	properties.Property("user A cannot see user B's activities through ListActivitiesByUser", prop.ForAll(
		func(numUsers int, activitiesPerUserBase int) bool {
			activityStore := NewIsolationActivityStore()
			ctx := context.Background()

			activityTypes := []string{"draft_created", "post_success", "post_failed"}

			// Create activities for each user with varying counts
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				// Vary activity count per user
				numActivities := (activitiesPerUserBase + i) % 10
				if numActivities == 0 {
					numActivities = 1
				}
				for j := 0; j < numActivities; j++ {
					activityType := activityTypes[j%len(activityTypes)]
					activityStore.CreateActivity(ctx, userID, activityType, nil)
				}
			}

			totalActivities := len(activityStore.GetAllActivities())

			// For each user, verify they only see their own activities
			sumOfUserActivities := 0
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				activities, _ := activityStore.ListActivitiesByUser(ctx, userID, 100, 0)
				sumOfUserActivities += len(activities)

				// Property: No activity from another user should appear
				for _, activity := range activities {
					if activity.UserID != userID {
						t.Logf("ISOLATION VIOLATION: User %s can see activity %s belonging to user %s",
							userID, activity.ID, activity.UserID)
						return false
					}
				}
			}

			// Property: Sum of all user-specific activities must equal total activities
			// (no duplicates, no missing activities)
			if sumOfUserActivities != totalActivities {
				t.Logf("Sum of user activities (%d) != total activities (%d)", sumOfUserActivities, totalActivities)
				return false
			}

			return true
		},
		numUsersGen,
		activitiesGen,
	))

	properties.TestingRun(t)
}

// TestProperty37_ActivityIsolation_NonexistentUserReturnsEmpty verifies that
// querying for a non-existent user returns empty results.
// Validates Requirement 14.3
func TestProperty37_ActivityIsolation_NonexistentUserReturnsEmpty(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(37)
	properties := gopter.NewProperties(parameters)

	properties.Property("ListActivitiesByUser returns empty for non-existent user", prop.ForAll(
		func(numActivities int) bool {
			activityStore := NewIsolationActivityStore()
			ctx := context.Background()

			// Create activities for various users
			for i := 0; i < numActivities; i++ {
				userID := fmt.Sprintf("user-%d", i)
				activityStore.CreateActivity(ctx, userID, "draft_created", nil)
			}

			// Query for a user that doesn't exist
			nonexistentUserID := "user-nonexistent-99999"
			activities, err := activityStore.ListActivitiesByUser(ctx, nonexistentUserID, 100, 0)
			if err != nil {
				t.Logf("Unexpected error: %v", err)
				return false
			}

			// Property: Must return empty slice for non-existent user
			if len(activities) != 0 {
				t.Logf("Expected 0 activities for non-existent user, got %d", len(activities))
				return false
			}

			return true
		},
		gen.IntRange(1, 20),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Property Tests: Combined Draft and Activity Isolation
// =============================================================================

// TestProperty37_CombinedIsolation_DraftsAndActivitiesIsolated verifies that
// both drafts and activities are isolated when created together.
// Validates Requirements 14.3, 14.4
func TestProperty37_CombinedIsolation_DraftsAndActivitiesIsolated(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(37)
	properties := gopter.NewProperties(parameters)

	// Generator for number of users (2-15)
	numUsersGen := gen.IntRange(2, 15)

	// Generator for operations per user (1-8)
	opsPerUserGen := gen.IntRange(1, 8)

	properties.Property("drafts and activities created together remain isolated per user", prop.ForAll(
		func(numUsers, opsPerUser int) bool {
			draftStore := NewIsolationDraftStore()
			activityStore := NewIsolationActivityStore()
			ctx := context.Background()

			// Simulate workflow: create draft -> create activity
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				for j := 0; j < opsPerUser; j++ {
					// Create draft
					draft, err := draftStore.CreateDraft(ctx, userID, fmt.Sprintf("repo-%d-%d", i, j), "refs/heads/main")
					if err != nil {
						return false
					}

					// Create associated activity
					draftID := draft.ID
					_, err = activityStore.CreateActivity(ctx, userID, "draft_created", &draftID)
					if err != nil {
						return false
					}
				}
			}

			// Verify each user's isolation
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)

				// Check drafts isolation
				drafts, _ := draftStore.ListDraftsByUser(ctx, userID)
				for _, draft := range drafts {
					if draft.UserID != userID {
						t.Logf("Draft isolation violation for user %s", userID)
						return false
					}
				}

				// Check activities isolation
				activities, _ := activityStore.ListActivitiesByUser(ctx, userID, 100, 0)
				for _, activity := range activities {
					if activity.UserID != userID {
						t.Logf("Activity isolation violation for user %s", userID)
						return false
					}
				}

				// Property: Number of drafts should equal number of activities for each user
				if len(drafts) != len(activities) {
					t.Logf("User %s has %d drafts but %d activities", userID, len(drafts), len(activities))
					return false
				}

				// Property: Each user should have opsPerUser drafts and activities
				if len(drafts) != opsPerUser {
					t.Logf("User %s has %d drafts, expected %d", userID, len(drafts), opsPerUser)
					return false
				}
			}

			return true
		},
		numUsersGen,
		opsPerUserGen,
	))

	properties.TestingRun(t)
}

// TestProperty37_Isolation_ActivitiesReferenceCorrectUserDrafts verifies that
// activities only reference drafts belonging to the same user.
// Validates Requirements 14.3, 14.4
func TestProperty37_Isolation_ActivitiesReferenceCorrectUserDrafts(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(37)
	properties := gopter.NewProperties(parameters)

	// Generator for number of users (2-10)
	numUsersGen := gen.IntRange(2, 10)

	properties.Property("activities only reference drafts belonging to the same user", prop.ForAll(
		func(numUsers int) bool {
			draftStore := NewIsolationDraftStore()
			activityStore := NewIsolationActivityStore()
			ctx := context.Background()

			// Create drafts and activities for each user
			userDrafts := make(map[string][]string) // userID -> list of draft IDs
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				userDrafts[userID] = []string{}

				// Create 1-3 drafts per user
				numDrafts := (i % 3) + 1
				for j := 0; j < numDrafts; j++ {
					draft, _ := draftStore.CreateDraft(ctx, userID, fmt.Sprintf("repo-%d-%d", i, j), "refs/heads/main")
					userDrafts[userID] = append(userDrafts[userID], draft.ID)

					// Create activity referencing this draft
					draftID := draft.ID
					activityStore.CreateActivity(ctx, userID, "draft_created", &draftID)
				}
			}

			// Verify activities reference correct user's drafts
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				activities, _ := activityStore.ListActivitiesByUser(ctx, userID, 100, 0)

				for _, activity := range activities {
					if activity.DraftID != nil {
						// Check that the referenced draft belongs to this user
						referencedDraftID := *activity.DraftID
						found := false
						for _, draftID := range userDrafts[userID] {
							if draftID == referencedDraftID {
								found = true
								break
							}
						}
						if !found {
							t.Logf("Activity %s for user %s references draft %s which doesn't belong to this user",
								activity.ID, userID, referencedDraftID)
							return false
						}
					}
				}
			}

			return true
		},
		numUsersGen,
	))

	properties.TestingRun(t)
}

// TestProperty37_Isolation_PaginationPreservesIsolation verifies that
// pagination does not leak data across users.
// Validates Requirements 14.3, 14.4
func TestProperty37_Isolation_PaginationPreservesIsolation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(37)
	properties := gopter.NewProperties(parameters)

	// Generator for number of users (2-5)
	numUsersGen := gen.IntRange(2, 5)

	// Generator for activities per user (5-20)
	activitiesPerUserGen := gen.IntRange(5, 20)

	// Generator for page size (1-10)
	pageSizeGen := gen.IntRange(1, 10)

	properties.Property("pagination preserves user isolation", prop.ForAll(
		func(numUsers, activitiesPerUser, pageSize int) bool {
			activityStore := NewIsolationActivityStore()
			ctx := context.Background()

			// Create activities for each user
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				for j := 0; j < activitiesPerUser; j++ {
					activityStore.CreateActivity(ctx, userID, "draft_created", nil)
				}
			}

			// Test pagination for each user
			for i := 0; i < numUsers; i++ {
				userID := fmt.Sprintf("user-%d", i)
				allUserActivities := make([]*IsolationActivity, 0)
				offset := 0

				// Paginate through all activities
				for {
					activities, _ := activityStore.ListActivitiesByUser(ctx, userID, pageSize, offset)
					if len(activities) == 0 {
						break
					}

					for _, activity := range activities {
						// Property: Each paginated result must belong to the user
						if activity.UserID != userID {
							t.Logf("Pagination leaked data: User %s saw activity from user %s", userID, activity.UserID)
							return false
						}
						allUserActivities = append(allUserActivities, activity)
					}

					offset += pageSize
					if len(activities) < pageSize {
						break
					}
				}

				// Property: Total paginated activities should equal user's activity count
				if len(allUserActivities) != activitiesPerUser {
					t.Logf("User %s: paginated %d activities, expected %d", userID, len(allUserActivities), activitiesPerUser)
					return false
				}
			}

			return true
		},
		numUsersGen,
		activitiesPerUserGen,
		pageSizeGen,
	))

	properties.TestingRun(t)
}
