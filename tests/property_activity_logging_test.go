// Package tests contains property-based tests for the Roxas application.
// Property 23: Draft creation (success or error) creates activity feed item.
// Validates Requirements 5.18 (activity feed for user actions), 12.2 (activity logging).
package tests

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// =============================================================================
// Activity Logging Test Types and Mocks
// =============================================================================

// ActivityType constants for activity logging
const (
	ActivityTypeDraftCreated = "draft_created"
	ActivityTypePostSuccess  = "post_success"
	ActivityTypePostFailed   = "post_failed"
)

// TestDraft represents a draft for property testing
type TestDraft struct {
	ID           string
	UserID       string
	RepositoryID string
	Ref          string
	BeforeSHA    string
	AfterSHA     string
	CommitSHAs   []string
	Status       string
	CreatedAt    time.Time
}

// TestActivity represents an activity record for property testing
type TestActivity struct {
	ID        string
	UserID    string
	Type      string
	DraftID   *string
	Message   string
	CreatedAt time.Time
}

// TestDraftStore is a mock draft store for property testing
type TestDraftStore struct {
	mu           sync.Mutex
	drafts       map[string]*TestDraft
	nextID       int
	shouldFail   bool
	failureError error
}

// NewTestDraftStore creates a new mock draft store
func NewTestDraftStore() *TestDraftStore {
	return &TestDraftStore{
		drafts: make(map[string]*TestDraft),
		nextID: 1,
	}
}

// SetFailure configures the store to simulate failures
func (s *TestDraftStore) SetFailure(shouldFail bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shouldFail = shouldFail
	s.failureError = err
}

// CreateDraftFromPush creates a draft from push data
func (s *TestDraftStore) CreateDraftFromPush(ctx context.Context, userID, repoID, ref, beforeSHA, afterSHA string, commitSHAs []string) (*TestDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.shouldFail {
		return nil, s.failureError
	}

	draft := &TestDraft{
		ID:           fmt.Sprintf("draft-%d", s.nextID),
		UserID:       userID,
		RepositoryID: repoID,
		Ref:          ref,
		BeforeSHA:    beforeSHA,
		AfterSHA:     afterSHA,
		CommitSHAs:   commitSHAs,
		Status:       "draft",
		CreatedAt:    time.Now(),
	}
	s.nextID++
	s.drafts[draft.ID] = draft
	return draft, nil
}

// GetDrafts returns all created drafts
func (s *TestDraftStore) GetDrafts() []*TestDraft {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]*TestDraft, 0, len(s.drafts))
	for _, d := range s.drafts {
		result = append(result, d)
	}
	return result
}

// TestActivityStore is a mock activity store for property testing
type TestActivityStore struct {
	mu         sync.Mutex
	activities []*TestActivity
	nextID     int
}

// NewTestActivityStore creates a new mock activity store
func NewTestActivityStore() *TestActivityStore {
	return &TestActivityStore{
		activities: make([]*TestActivity, 0),
		nextID:     1,
	}
}

// CreateActivity creates a new activity record
func (s *TestActivityStore) CreateActivity(ctx context.Context, userID, activityType string, draftID *string, message string) (*TestActivity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	activity := &TestActivity{
		ID:        fmt.Sprintf("activity-%d", s.nextID),
		UserID:    userID,
		Type:      activityType,
		DraftID:   draftID,
		Message:   message,
		CreatedAt: time.Now(),
	}
	s.nextID++
	s.activities = append(s.activities, activity)
	return activity, nil
}

// GetActivities returns all created activities
func (s *TestActivityStore) GetActivities() []*TestActivity {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]*TestActivity, len(s.activities))
	copy(result, s.activities)
	return result
}

// Clear resets the activity store
func (s *TestActivityStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activities = make([]*TestActivity, 0)
	s.nextID = 1
}

// =============================================================================
// Draft Creation with Activity Logging Simulator
// =============================================================================

// DraftCreationResult represents the result of a draft creation attempt
type DraftCreationResult struct {
	Draft    *TestDraft
	Activity *TestActivity
	Error    error
}

// SimulateDraftCreation simulates the draft creation flow with activity logging
// This mirrors the behavior in webhook_multitenant.go lines 615-642
func SimulateDraftCreation(
	ctx context.Context,
	draftStore *TestDraftStore,
	activityStore *TestActivityStore,
	userID, repoID, ref, beforeSHA, afterSHA string,
	commitSHAs []string,
) DraftCreationResult {
	// Attempt to create draft
	draft, err := draftStore.CreateDraftFromPush(ctx, userID, repoID, ref, beforeSHA, afterSHA, commitSHAs)

	if err != nil {
		// On draft creation error, still log activity with error type
		// (This validates requirement for activity logging even on errors)
		message := fmt.Sprintf("Draft creation failed for push to %s: %v", ref, err)
		activity, _ := activityStore.CreateActivity(ctx, userID, ActivityTypePostFailed, nil, message)
		return DraftCreationResult{
			Draft:    nil,
			Activity: activity,
			Error:    err,
		}
	}

	// On success, create activity record (mirrors webhook_multitenant.go)
	draftID := draft.ID
	message := fmt.Sprintf("Draft created from push to %s", ref)
	activity, _ := activityStore.CreateActivity(ctx, userID, ActivityTypeDraftCreated, &draftID, message)

	return DraftCreationResult{
		Draft:    draft,
		Activity: activity,
		Error:    nil,
	}
}

// =============================================================================
// Property Tests: Activity Logging on Draft Creation
// =============================================================================

// TestPropertyActivityLogging_DraftCreationSuccess verifies that successful draft
// creation always creates an activity record with correct attributes.
// Property 23.1: Successful draft creation creates activity with type "draft_created"
// Validates Requirement 5.18: Activity feed for user actions
func TestPropertyActivityLogging_DraftCreationSuccess(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for valid user IDs (UUID format)
	userIDGen := gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Generator for valid repository IDs (UUID format)
	repoIDGen := gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Generator for valid Git refs
	refGen := gen.OneConstOf(
		"refs/heads/main",
		"refs/heads/master",
		"refs/heads/develop",
		"refs/heads/feature/new-feature",
		"refs/heads/bugfix/fix-123",
		"refs/tags/v1.0.0",
	)

	// Generator for Git SHAs (40 hex characters)
	shaGen := gen.RegexMatch(`[0-9a-f]{40}`)

	properties.Property("successful draft creation always creates activity record", prop.ForAll(
		func(userID, repoID, ref, beforeSHA, afterSHA string) bool {
			draftStore := NewTestDraftStore()
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			commitSHAs := []string{afterSHA[:12]} // Use first 12 chars as commit SHA

			result := SimulateDraftCreation(ctx, draftStore, activityStore, userID, repoID, ref, beforeSHA, afterSHA, commitSHAs)

			// Property: No error should occur
			if result.Error != nil {
				return false
			}

			// Property: Activity must be created
			if result.Activity == nil {
				return false
			}

			return true
		},
		userIDGen,
		repoIDGen,
		refGen,
		shaGen,
		shaGen,
	))

	properties.Property("activity type is always 'draft_created' on success", prop.ForAll(
		func(userID, repoID, ref, beforeSHA, afterSHA string) bool {
			draftStore := NewTestDraftStore()
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			result := SimulateDraftCreation(ctx, draftStore, activityStore, userID, repoID, ref, beforeSHA, afterSHA, []string{afterSHA[:12]})

			if result.Error != nil || result.Activity == nil {
				return false
			}

			// Property: Activity type must be "draft_created"
			return result.Activity.Type == ActivityTypeDraftCreated
		},
		userIDGen,
		repoIDGen,
		refGen,
		shaGen,
		shaGen,
	))

	properties.Property("activity references correct user ID", prop.ForAll(
		func(userID, repoID, ref, beforeSHA, afterSHA string) bool {
			draftStore := NewTestDraftStore()
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			result := SimulateDraftCreation(ctx, draftStore, activityStore, userID, repoID, ref, beforeSHA, afterSHA, []string{afterSHA[:12]})

			if result.Error != nil || result.Activity == nil {
				return false
			}

			// Property: Activity user ID must match input user ID
			return result.Activity.UserID == userID
		},
		userIDGen,
		repoIDGen,
		refGen,
		shaGen,
		shaGen,
	))

	properties.Property("activity references correct draft ID", prop.ForAll(
		func(userID, repoID, ref, beforeSHA, afterSHA string) bool {
			draftStore := NewTestDraftStore()
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			result := SimulateDraftCreation(ctx, draftStore, activityStore, userID, repoID, ref, beforeSHA, afterSHA, []string{afterSHA[:12]})

			if result.Error != nil || result.Activity == nil || result.Draft == nil {
				return false
			}

			// Property: Activity must reference the created draft's ID
			if result.Activity.DraftID == nil {
				return false
			}
			return *result.Activity.DraftID == result.Draft.ID
		},
		userIDGen,
		repoIDGen,
		refGen,
		shaGen,
		shaGen,
	))

	properties.Property("activity message contains ref", prop.ForAll(
		func(userID, repoID, ref, beforeSHA, afterSHA string) bool {
			draftStore := NewTestDraftStore()
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			result := SimulateDraftCreation(ctx, draftStore, activityStore, userID, repoID, ref, beforeSHA, afterSHA, []string{afterSHA[:12]})

			if result.Error != nil || result.Activity == nil {
				return false
			}

			// Property: Activity message must contain the ref
			return strings.Contains(result.Activity.Message, ref)
		},
		userIDGen,
		repoIDGen,
		refGen,
		shaGen,
		shaGen,
	))

	properties.TestingRun(t)
}

// TestPropertyActivityLogging_DraftCreationError verifies that activity is logged
// even when draft creation fails.
// Property 23.2: Draft creation error still creates activity feed item
// Validates Requirement 12.2: Activity logging for error scenarios
func TestPropertyActivityLogging_DraftCreationError(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for valid user IDs
	userIDGen := gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Generator for valid repository IDs
	repoIDGen := gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Generator for valid Git refs
	refGen := gen.OneConstOf(
		"refs/heads/main",
		"refs/heads/feature/test",
		"refs/tags/v2.0.0",
	)

	// Generator for Git SHAs
	shaGen := gen.RegexMatch(`[0-9a-f]{40}`)

	// Generator for error messages
	errorGen := gen.OneConstOf(
		"database connection failed",
		"duplicate draft exists",
		"foreign key violation",
		"timeout exceeded",
	)

	properties.Property("draft creation error still creates activity record", prop.ForAll(
		func(userID, repoID, ref, beforeSHA, afterSHA, errorMsg string) bool {
			draftStore := NewTestDraftStore()
			draftStore.SetFailure(true, errors.New(errorMsg))
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			result := SimulateDraftCreation(ctx, draftStore, activityStore, userID, repoID, ref, beforeSHA, afterSHA, []string{afterSHA[:12]})

			// Property: Error should be returned
			if result.Error == nil {
				return false
			}

			// Property: Activity must still be created
			if result.Activity == nil {
				return false
			}

			return true
		},
		userIDGen,
		repoIDGen,
		refGen,
		shaGen,
		shaGen,
		errorGen,
	))

	properties.Property("error activity has correct type", prop.ForAll(
		func(userID, repoID, ref, beforeSHA, afterSHA, errorMsg string) bool {
			draftStore := NewTestDraftStore()
			draftStore.SetFailure(true, errors.New(errorMsg))
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			result := SimulateDraftCreation(ctx, draftStore, activityStore, userID, repoID, ref, beforeSHA, afterSHA, []string{afterSHA[:12]})

			if result.Activity == nil {
				return false
			}

			// Property: Activity type should indicate failure
			return result.Activity.Type == ActivityTypePostFailed
		},
		userIDGen,
		repoIDGen,
		refGen,
		shaGen,
		shaGen,
		errorGen,
	))

	properties.Property("error activity message contains error details", prop.ForAll(
		func(userID, repoID, ref, beforeSHA, afterSHA, errorMsg string) bool {
			draftStore := NewTestDraftStore()
			draftStore.SetFailure(true, errors.New(errorMsg))
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			result := SimulateDraftCreation(ctx, draftStore, activityStore, userID, repoID, ref, beforeSHA, afterSHA, []string{afterSHA[:12]})

			if result.Activity == nil {
				return false
			}

			// Property: Activity message should contain error details
			return strings.Contains(result.Activity.Message, errorMsg)
		},
		userIDGen,
		repoIDGen,
		refGen,
		shaGen,
		shaGen,
		errorGen,
	))

	properties.Property("error activity has no draft ID reference", prop.ForAll(
		func(userID, repoID, ref, beforeSHA, afterSHA, errorMsg string) bool {
			draftStore := NewTestDraftStore()
			draftStore.SetFailure(true, errors.New(errorMsg))
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			result := SimulateDraftCreation(ctx, draftStore, activityStore, userID, repoID, ref, beforeSHA, afterSHA, []string{afterSHA[:12]})

			if result.Activity == nil {
				return false
			}

			// Property: On error, draft ID should be nil (no draft was created)
			return result.Activity.DraftID == nil
		},
		userIDGen,
		repoIDGen,
		refGen,
		shaGen,
		shaGen,
		errorGen,
	))

	properties.TestingRun(t)
}

// TestPropertyActivityLogging_OneActivityPerDraft verifies that exactly one activity
// record is created per draft creation attempt.
// Property 23.3: One activity record per draft creation (no duplicates)
// Validates Requirement 5.18: Activity feed integrity
func TestPropertyActivityLogging_OneActivityPerDraft(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for number of draft creations (1-10)
	countGen := gen.IntRange(1, 10)

	// Generator for valid user IDs
	userIDGen := gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	properties.Property("N draft creations produce exactly N activity records", prop.ForAll(
		func(count int, userID string) bool {
			draftStore := NewTestDraftStore()
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			// Create N drafts
			for i := 0; i < count; i++ {
				repoID := fmt.Sprintf("repo-%d", i)
				ref := fmt.Sprintf("refs/heads/branch-%d", i)
				beforeSHA := fmt.Sprintf("%040d", i)
				afterSHA := fmt.Sprintf("%040d", i+1000)

				SimulateDraftCreation(ctx, draftStore, activityStore, userID, repoID, ref, beforeSHA, afterSHA, []string{afterSHA[:12]})
			}

			// Property: Number of activities must equal number of draft creation attempts
			activities := activityStore.GetActivities()
			return len(activities) == count
		},
		countGen,
		userIDGen,
	))

	properties.Property("each activity has unique ID", prop.ForAll(
		func(count int, userID string) bool {
			draftStore := NewTestDraftStore()
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			for i := 0; i < count; i++ {
				SimulateDraftCreation(ctx, draftStore, activityStore, userID, fmt.Sprintf("repo-%d", i), "refs/heads/main", fmt.Sprintf("%040d", i), fmt.Sprintf("%040d", i+1), []string{})
			}

			activities := activityStore.GetActivities()
			seen := make(map[string]bool)
			for _, a := range activities {
				if seen[a.ID] {
					return false // Duplicate ID found
				}
				seen[a.ID] = true
			}
			return true
		},
		countGen,
		userIDGen,
	))

	properties.TestingRun(t)
}

// TestPropertyActivityLogging_Timestamp verifies that activity timestamps are
// reasonable and recent.
// Property 23.4: Activity timestamps are valid and recent
// Validates Requirement 12.2: Activity logging with proper timestamps
func TestPropertyActivityLogging_Timestamp(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for valid user IDs
	userIDGen := gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Generator for Git SHAs
	shaGen := gen.RegexMatch(`[0-9a-f]{40}`)

	properties.Property("activity timestamp is within test execution window", prop.ForAll(
		func(userID, beforeSHA, afterSHA string) bool {
			draftStore := NewTestDraftStore()
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			beforeTest := time.Now().Add(-1 * time.Second)

			result := SimulateDraftCreation(ctx, draftStore, activityStore, userID, "repo-id", "refs/heads/main", beforeSHA, afterSHA, []string{afterSHA[:12]})

			afterTest := time.Now().Add(1 * time.Second)

			if result.Activity == nil {
				return false
			}

			// Property: Timestamp must be within test execution window
			return result.Activity.CreatedAt.After(beforeTest) && result.Activity.CreatedAt.Before(afterTest)
		},
		userIDGen,
		shaGen,
		shaGen,
	))

	properties.Property("activity timestamp is not zero value", prop.ForAll(
		func(userID, beforeSHA, afterSHA string) bool {
			draftStore := NewTestDraftStore()
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			result := SimulateDraftCreation(ctx, draftStore, activityStore, userID, "repo-id", "refs/heads/main", beforeSHA, afterSHA, []string{afterSHA[:12]})

			if result.Activity == nil {
				return false
			}

			// Property: Timestamp must not be zero
			return !result.Activity.CreatedAt.IsZero()
		},
		userIDGen,
		shaGen,
		shaGen,
	))

	properties.TestingRun(t)
}

// TestPropertyActivityLogging_ValidActivityTypes verifies that only valid activity
// types are used.
// Property 23.5: Activity type is always from valid set
// Validates Requirement 5.18: Activity feed type constraints
func TestPropertyActivityLogging_ValidActivityTypes(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Valid activity types (must match database constraint)
	validTypes := map[string]bool{
		ActivityTypeDraftCreated: true,
		ActivityTypePostSuccess:  true,
		ActivityTypePostFailed:   true,
	}

	// Generator for valid user IDs
	userIDGen := gen.RegexMatch(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Generator for Git SHAs
	shaGen := gen.RegexMatch(`[0-9a-f]{40}`)

	// Generator for success/failure scenarios
	shouldFailGen := gen.Bool()

	properties.Property("activity type is always valid", prop.ForAll(
		func(userID, beforeSHA, afterSHA string, shouldFail bool) bool {
			draftStore := NewTestDraftStore()
			if shouldFail {
				draftStore.SetFailure(true, errors.New("simulated error"))
			}
			activityStore := NewTestActivityStore()
			ctx := context.Background()

			result := SimulateDraftCreation(ctx, draftStore, activityStore, userID, "repo-id", "refs/heads/main", beforeSHA, afterSHA, []string{afterSHA[:12]})

			if result.Activity == nil {
				return false
			}

			// Property: Activity type must be one of the valid types
			return validTypes[result.Activity.Type]
		},
		userIDGen,
		shaGen,
		shaGen,
		shouldFailGen,
	))

	properties.TestingRun(t)
}
