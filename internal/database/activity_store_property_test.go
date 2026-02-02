package database

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/mikelady/roxas/internal/web"
)

// Property Test: Activity Feed Pagination (Property 29)
// Validates Requirements 8.1, 8.6
//
// Property: Activity feed returns 20 most recent items sorted by created_at DESC,
// with correct pagination. "Load more" fetches the next 20 items.

// MockActivityStore provides an in-memory implementation for property testing
type MockActivityStore struct {
	activities map[string][]*web.DashboardActivity // userID -> activities
}

func NewMockActivityStore() *MockActivityStore {
	return &MockActivityStore{
		activities: make(map[string][]*web.DashboardActivity),
	}
}

// ListActivitiesByUser implements the same pagination logic as the real store
func (m *MockActivityStore) ListActivitiesByUser(ctx context.Context, userID string, limit, offset int) ([]*web.DashboardActivity, error) {
	if limit <= 0 {
		limit = 20 // Default limit (Req 8.1: display 20 most recent)
	}
	if limit > 100 {
		limit = 100 // Max limit
	}
	if offset < 0 {
		offset = 0
	}

	userActivities := m.activities[userID]
	if userActivities == nil {
		return []*web.DashboardActivity{}, nil
	}

	// Sort by created_at DESC (newest first)
	sorted := make([]*web.DashboardActivity, len(userActivities))
	copy(sorted, userActivities)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CreatedAt.After(sorted[j].CreatedAt)
	})

	// Apply offset
	start := offset
	if start >= len(sorted) {
		return []*web.DashboardActivity{}, nil
	}

	// Apply limit
	end := start + limit
	if end > len(sorted) {
		end = len(sorted)
	}

	return sorted[start:end], nil
}

func (m *MockActivityStore) CountActivitiesByUser(ctx context.Context, userID string) (int, error) {
	return len(m.activities[userID]), nil
}

// AddActivity adds an activity with a random timestamp for testing
func (m *MockActivityStore) AddActivity(userID string, activityType string, createdAt time.Time) {
	activity := &web.DashboardActivity{
		ID:        uuid.New().String(),
		Type:      activityType,
		CreatedAt: createdAt,
	}
	m.activities[userID] = append(m.activities[userID], activity)
}

// TestProperty29_ActivityFeedPagination tests the activity feed pagination properties
func TestProperty29_ActivityFeedPagination(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Property 29a: Default limit returns 20 items (Req 8.1)
	properties.Property("default limit returns up to 20 items", prop.ForAll(
		func(numActivities int) bool {
			store := NewMockActivityStore()
			userID := uuid.New().String()
			baseTime := time.Now()

			// Add activities with unique timestamps
			for i := 0; i < numActivities; i++ {
				store.AddActivity(userID, "draft_created", baseTime.Add(time.Duration(i)*time.Second))
			}

			// Fetch with limit=0 (should default to 20)
			activities, err := store.ListActivitiesByUser(context.Background(), userID, 0, 0)
			if err != nil {
				return false
			}

			expectedCount := numActivities
			if expectedCount > 20 {
				expectedCount = 20
			}

			return len(activities) == expectedCount
		},
		gen.IntRange(0, 50),
	))

	// Property 29b: Results are sorted by created_at DESC (newest first) (Req 8.1)
	properties.Property("results are sorted by created_at DESC", prop.ForAll(
		func(numActivities int) bool {
			if numActivities < 2 {
				return true // Need at least 2 items to verify order
			}

			store := NewMockActivityStore()
			userID := uuid.New().String()
			baseTime := time.Now()

			// Add activities with unique timestamps
			for i := 0; i < numActivities; i++ {
				store.AddActivity(userID, "draft_created", baseTime.Add(time.Duration(i)*time.Second))
			}

			activities, err := store.ListActivitiesByUser(context.Background(), userID, 100, 0)
			if err != nil {
				return false
			}

			// Verify descending order (newest first)
			for i := 1; i < len(activities); i++ {
				if activities[i].CreatedAt.After(activities[i-1].CreatedAt) {
					return false // Not in DESC order
				}
			}

			return true
		},
		gen.IntRange(2, 50),
	))

	// Property 29c: Pagination offset returns correct items (Req 8.6)
	properties.Property("pagination offset returns correct subsequent items", prop.ForAll(
		func(numActivities, offset int) bool {
			if numActivities == 0 {
				return true
			}

			store := NewMockActivityStore()
			userID := uuid.New().String()
			baseTime := time.Now()

			// Add activities with unique timestamps
			for i := 0; i < numActivities; i++ {
				store.AddActivity(userID, "draft_created", baseTime.Add(time.Duration(i)*time.Second))
			}

			// Get all activities first
			allActivities, _ := store.ListActivitiesByUser(context.Background(), userID, 100, 0)

			// Get activities with offset
			offsetActivities, err := store.ListActivitiesByUser(context.Background(), userID, 20, offset)
			if err != nil {
				return false
			}

			// If offset >= total, should return empty
			if offset >= len(allActivities) {
				return len(offsetActivities) == 0
			}

			// Verify offset activities match expected slice
			expectedEnd := offset + 20
			if expectedEnd > len(allActivities) {
				expectedEnd = len(allActivities)
			}
			expected := allActivities[offset:expectedEnd]

			if len(offsetActivities) != len(expected) {
				return false
			}

			for i := range offsetActivities {
				if offsetActivities[i].ID != expected[i].ID {
					return false
				}
			}

			return true
		},
		gen.IntRange(0, 100),
		gen.IntRange(0, 50),
	))

	// Property 29d: Load more returns next 20 items without overlap (Req 8.6)
	properties.Property("load more returns next 20 items without overlap", prop.ForAll(
		func(numActivities int) bool {
			if numActivities <= 20 {
				return true // Need more than 20 to test "load more"
			}

			store := NewMockActivityStore()
			userID := uuid.New().String()
			baseTime := time.Now()

			// Add activities with unique timestamps
			for i := 0; i < numActivities; i++ {
				store.AddActivity(userID, "draft_created", baseTime.Add(time.Duration(i)*time.Second))
			}

			// First page (most recent 20)
			firstPage, err := store.ListActivitiesByUser(context.Background(), userID, 20, 0)
			if err != nil {
				return false
			}

			// Second page (load more: next 20)
			secondPage, err := store.ListActivitiesByUser(context.Background(), userID, 20, 20)
			if err != nil {
				return false
			}

			// Verify first page has 20 items
			if len(firstPage) != 20 {
				return false
			}

			// Verify no overlap between pages
			firstPageIDs := make(map[string]bool)
			for _, a := range firstPage {
				firstPageIDs[a.ID] = true
			}
			for _, a := range secondPage {
				if firstPageIDs[a.ID] {
					return false // Found overlap
				}
			}

			// Verify second page items are older than first page items
			if len(secondPage) > 0 {
				oldestFirstPage := firstPage[len(firstPage)-1].CreatedAt
				newestSecondPage := secondPage[0].CreatedAt
				if newestSecondPage.After(oldestFirstPage) {
					return false // Second page has newer items
				}
			}

			return true
		},
		gen.IntRange(21, 100),
	))

	// Property 29e: Total count matches actual activities for user
	properties.Property("total count matches actual activities", prop.ForAll(
		func(numActivities int) bool {
			store := NewMockActivityStore()
			userID := uuid.New().String()
			baseTime := time.Now()

			for i := 0; i < numActivities; i++ {
				store.AddActivity(userID, "draft_created", baseTime.Add(time.Duration(i)*time.Second))
			}

			count, err := store.CountActivitiesByUser(context.Background(), userID)
			if err != nil {
				return false
			}

			return count == numActivities
		},
		gen.IntRange(0, 100),
	))

	// Property 29f: User isolation - activities belong only to requested user
	properties.Property("user isolation - activities only for requested user", prop.ForAll(
		func(numUsers, activitiesPerUser int) bool {
			if numUsers < 2 || activitiesPerUser == 0 {
				return true
			}

			store := NewMockActivityStore()
			userIDs := make([]string, numUsers)
			baseTime := time.Now()

			// Create activities for multiple users
			for u := 0; u < numUsers; u++ {
				userIDs[u] = uuid.New().String()
				for i := 0; i < activitiesPerUser; i++ {
					store.AddActivity(userIDs[u], "draft_created", baseTime.Add(time.Duration(u*100+i)*time.Second))
				}
			}

			// Verify each user only sees their own activities
			for _, userID := range userIDs {
				activities, err := store.ListActivitiesByUser(context.Background(), userID, 100, 0)
				if err != nil {
					return false
				}

				// Verify correct count
				if len(activities) != activitiesPerUser {
					return false
				}
			}

			return true
		},
		gen.IntRange(2, 10),
		gen.IntRange(1, 30),
	))

	// Property 29g: Negative offset is treated as 0
	properties.Property("negative offset is treated as zero", prop.ForAll(
		func(numActivities, negativeOffset int) bool {
			store := NewMockActivityStore()
			userID := uuid.New().String()
			baseTime := time.Now()

			for i := 0; i < numActivities; i++ {
				store.AddActivity(userID, "draft_created", baseTime.Add(time.Duration(i)*time.Second))
			}

			// Get with negative offset
			negativeResult, err := store.ListActivitiesByUser(context.Background(), userID, 20, -negativeOffset)
			if err != nil {
				return false
			}

			// Get with zero offset
			zeroResult, err := store.ListActivitiesByUser(context.Background(), userID, 20, 0)
			if err != nil {
				return false
			}

			// Should be equivalent
			if len(negativeResult) != len(zeroResult) {
				return false
			}
			for i := range negativeResult {
				if negativeResult[i].ID != zeroResult[i].ID {
					return false
				}
			}

			return true
		},
		gen.IntRange(1, 50),
		gen.IntRange(1, 100),
	))

	// Property 29h: Limit is clamped to max 100
	properties.Property("limit is clamped to max 100", prop.ForAll(
		func(numActivities, requestedLimit int) bool {
			store := NewMockActivityStore()
			userID := uuid.New().String()
			baseTime := time.Now()

			for i := 0; i < numActivities; i++ {
				store.AddActivity(userID, "draft_created", baseTime.Add(time.Duration(i)*time.Second))
			}

			activities, err := store.ListActivitiesByUser(context.Background(), userID, requestedLimit, 0)
			if err != nil {
				return false
			}

			// Effective limit is min(requestedLimit clamped to [1,100], numActivities)
			effectiveLimit := requestedLimit
			if effectiveLimit <= 0 {
				effectiveLimit = 20
			}
			if effectiveLimit > 100 {
				effectiveLimit = 100
			}
			expectedCount := effectiveLimit
			if expectedCount > numActivities {
				expectedCount = numActivities
			}

			return len(activities) == expectedCount
		},
		gen.IntRange(50, 200), // More activities than max limit
		gen.IntRange(50, 200), // Requested limits above max
	))

	properties.TestingRun(t)
}
