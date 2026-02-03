package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ActivityStore Mock Tests
//
// This file demonstrates the standard patterns for testing database stores using pgxmock.
// Use these patterns as a reference when writing tests for other stores.
//
// KEY PATTERNS DEMONSTRATED:
//
// 1. Basic QueryRow with Scan (CreateActivity, GetActivityByID)
// 2. Query returning multiple rows (ListActivitiesByUser)
// 3. QueryRow for aggregation (CountActivitiesByUser)
// 4. Error handling (not found, database errors)
// 5. Input validation (invalid activity type)
// 6. NULL handling with pointers
//
// TESTING CHECKLIST FOR STORE METHODS:
//
// For each store method, test:
// - [ ] Happy path with valid input
// - [ ] Not found / empty result
// - [ ] Database error propagation
// - [ ] Input validation (if any)
// - [ ] NULL handling for optional fields
// - [ ] Edge cases (empty strings, zero values, etc.)

// TestActivityStore_CreateActivity_Success tests successful activity creation.
// Pattern: QueryRow with INSERT...RETURNING and multiple columns.
func TestActivityStore_CreateActivity_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewActivityStoreWithDB(mock)

	// Test data
	userID := "user-123"
	activityType := "draft_created"
	draftID := "draft-456"
	now := time.Now().Truncate(time.Microsecond) // Truncate for DB precision

	// Set up expected query
	// Note: pgxmock uses regexp matching by default
	// Use pgxmock.AnyArg() for optional pointer arguments to avoid nil type matching issues
	rows := pgxmock.NewRows([]string{"id", "user_id", "type", "draft_id", "post_id", "platform", "message", "created_at"}).
		AddRow("activity-789", userID, activityType, &draftID, nil, nil, nil, now)

	mock.ExpectQuery(`INSERT INTO activities`).
		WithArgs(userID, activityType, &draftID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(rows)

	// Execute
	activity, err := store.CreateActivity(context.Background(), userID, activityType, &draftID, nil, nil, nil)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, activity)
	assert.Equal(t, "activity-789", activity.ID)
	assert.Equal(t, userID, activity.UserID)
	assert.Equal(t, activityType, activity.Type)
	assert.Equal(t, &draftID, activity.DraftID)
	assert.Nil(t, activity.PostID)
}

// TestActivityStore_CreateActivity_WithAllFields tests creation with all optional fields populated.
// Pattern: Testing with non-nil pointer values for optional columns.
func TestActivityStore_CreateActivity_WithAllFields(t *testing.T) {
	mock := NewMockPool(t)
	store := NewActivityStoreWithDB(mock)

	userID := "user-123"
	activityType := "post_success"
	draftID := "draft-456"
	postID := "post-789"
	platform := "linkedin"
	message := "Posted successfully"
	now := time.Now().Truncate(time.Microsecond)

	rows := pgxmock.NewRows([]string{"id", "user_id", "type", "draft_id", "post_id", "platform", "message", "created_at"}).
		AddRow("activity-001", userID, activityType, &draftID, &postID, &platform, &message, now)

	mock.ExpectQuery(`INSERT INTO activities`).
		WithArgs(userID, activityType, &draftID, &postID, &platform, &message).
		WillReturnRows(rows)

	activity, err := store.CreateActivity(context.Background(), userID, activityType, &draftID, &postID, &platform, &message)

	require.NoError(t, err)
	require.NotNil(t, activity)
	assert.Equal(t, &postID, activity.PostID)
	assert.Equal(t, &platform, activity.Platform)
	assert.Equal(t, &message, activity.Message)
}

// TestActivityStore_CreateActivity_InvalidType tests input validation.
// Pattern: Testing validation that happens before database interaction.
func TestActivityStore_CreateActivity_InvalidType(t *testing.T) {
	mock := NewMockPool(t)
	store := NewActivityStoreWithDB(mock)

	// No database expectations - validation should fail before query

	activity, err := store.CreateActivity(context.Background(), "user-123", "invalid_type", nil, nil, nil, nil)

	assert.ErrorIs(t, err, ErrInvalidActivity)
	assert.Nil(t, activity)
}

// TestActivityStore_CreateActivity_DatabaseError tests database error propagation.
// Pattern: Using WillReturnError to simulate database failures.
func TestActivityStore_CreateActivity_DatabaseError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewActivityStoreWithDB(mock)

	dbErr := errors.New("connection refused")
	mock.ExpectQuery(`INSERT INTO activities`).
		WithArgs("user-123", "draft_created", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnError(dbErr)

	activity, err := store.CreateActivity(context.Background(), "user-123", "draft_created", nil, nil, nil, nil)

	assert.Error(t, err)
	assert.ErrorIs(t, err, dbErr)
	assert.Nil(t, activity)
}

// TestActivityStore_GetActivityByID_Success tests successful retrieval.
// Pattern: QueryRow with SELECT and scanning all columns.
func TestActivityStore_GetActivityByID_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewActivityStoreWithDB(mock)

	activityID := "activity-123"
	userID := "user-456"
	draftID := "draft-789"
	now := time.Now().Truncate(time.Microsecond)

	rows := pgxmock.NewRows([]string{"id", "user_id", "type", "draft_id", "post_id", "platform", "message", "created_at"}).
		AddRow(activityID, userID, "draft_created", &draftID, nil, nil, nil, now)

	mock.ExpectQuery(`SELECT id, user_id, type, draft_id, post_id, platform, message, created_at`).
		WithArgs(activityID).
		WillReturnRows(rows)

	activity, err := store.GetActivityByID(context.Background(), activityID)

	require.NoError(t, err)
	require.NotNil(t, activity)
	assert.Equal(t, activityID, activity.ID)
	assert.Equal(t, userID, activity.UserID)
	assert.Equal(t, now, activity.CreatedAt)
}

// TestActivityStore_GetActivityByID_NotFound tests the not found case.
// Pattern: Return nil, nil when record doesn't exist (per interface contract).
func TestActivityStore_GetActivityByID_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewActivityStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, user_id, type`).
		WithArgs("nonexistent-id").
		WillReturnError(pgx.ErrNoRows)

	activity, err := store.GetActivityByID(context.Background(), "nonexistent-id")

	assert.NoError(t, err)
	assert.Nil(t, activity)
}

// TestActivityStore_ListActivitiesByUser_Success tests listing with multiple results.
// Pattern: Query returning multiple rows with iteration.
func TestActivityStore_ListActivitiesByUser_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewActivityStoreWithDB(mock)

	userID := "user-123"
	now := time.Now().Truncate(time.Microsecond)
	earlier := now.Add(-1 * time.Hour)
	draftID1 := "draft-1"
	draftID2 := "draft-2"

	rows := pgxmock.NewRows([]string{"id", "type", "draft_id", "post_id", "platform", "message", "created_at"}).
		AddRow("activity-1", "draft_created", &draftID1, nil, nil, nil, now).
		AddRow("activity-2", "draft_created", &draftID2, nil, nil, nil, earlier)

	mock.ExpectQuery(`SELECT id, type, draft_id, post_id, platform, message, created_at`).
		WithArgs(userID, 20, 0).
		WillReturnRows(rows)

	activities, err := store.ListActivitiesByUser(context.Background(), userID, 0, 0)

	require.NoError(t, err)
	require.Len(t, activities, 2)
	assert.Equal(t, "activity-1", activities[0].ID)
	assert.Equal(t, "activity-2", activities[1].ID)
}

// TestActivityStore_ListActivitiesByUser_EmptyResult tests empty list handling.
// Pattern: Query returning zero rows.
func TestActivityStore_ListActivitiesByUser_EmptyResult(t *testing.T) {
	mock := NewMockPool(t)
	store := NewActivityStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"id", "type", "draft_id", "post_id", "platform", "message", "created_at"})

	mock.ExpectQuery(`SELECT id, type, draft_id`).
		WithArgs("user-with-no-activities", 20, 0).
		WillReturnRows(rows)

	activities, err := store.ListActivitiesByUser(context.Background(), "user-with-no-activities", 0, 0)

	require.NoError(t, err)
	assert.Empty(t, activities)
}

// TestActivityStore_ListActivitiesByUser_Pagination tests pagination parameter handling.
// Pattern: Testing default values and limits for pagination.
func TestActivityStore_ListActivitiesByUser_Pagination(t *testing.T) {
	testCases := []struct {
		name           string
		inputLimit     int
		inputOffset    int
		expectedLimit  int
		expectedOffset int
	}{
		{"default limit", 0, 0, 20, 0},
		{"custom limit", 50, 10, 50, 10},
		{"max limit enforced", 200, 0, 100, 0},
		{"negative offset normalized", 10, -5, 10, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := NewMockPool(t)
			store := NewActivityStoreWithDB(mock)

			rows := pgxmock.NewRows([]string{"id", "type", "draft_id", "post_id", "platform", "message", "created_at"})

			mock.ExpectQuery(`SELECT id, type`).
				WithArgs("user-123", tc.expectedLimit, tc.expectedOffset).
				WillReturnRows(rows)

			_, err := store.ListActivitiesByUser(context.Background(), "user-123", tc.inputLimit, tc.inputOffset)
			require.NoError(t, err)
		})
	}
}

// TestActivityStore_CountActivitiesByUser_Success tests count aggregation.
// Pattern: QueryRow with COUNT(*) returning a single scalar value.
func TestActivityStore_CountActivitiesByUser_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewActivityStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"count"}).AddRow(42)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM activities WHERE user_id`).
		WithArgs("user-123").
		WillReturnRows(rows)

	count, err := store.CountActivitiesByUser(context.Background(), "user-123")

	require.NoError(t, err)
	assert.Equal(t, 42, count)
}

// TestActivityStore_CountActivitiesByUser_ZeroCount tests zero count handling.
// Pattern: COUNT(*) always returns a row, even when count is 0.
func TestActivityStore_CountActivitiesByUser_ZeroCount(t *testing.T) {
	mock := NewMockPool(t)
	store := NewActivityStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"count"}).AddRow(0)

	mock.ExpectQuery(`SELECT COUNT\(\*\)`).
		WithArgs("user-with-no-activities").
		WillReturnRows(rows)

	count, err := store.CountActivitiesByUser(context.Background(), "user-with-no-activities")

	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
