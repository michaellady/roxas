package database

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mikelady/roxas/internal/web"
)

// Activity-related errors
var (
	ErrActivityNotFound = errors.New("activity not found")
	ErrInvalidActivity  = errors.New("invalid activity type")
)

// Valid activity types (must match DB check constraint)
var validActivityTypes = map[string]bool{
	"draft_created": true,
	"post_success":  true,
	"post_failed":   true,
}

// Compile-time interface compliance check
var _ web.ActivityLister = (*ActivityStore)(nil)

// ActivityStore implements web.ActivityLister using PostgreSQL
type ActivityStore struct {
	db DBTX
}

// NewActivityStore creates a new database-backed activity store
func NewActivityStore(pool *Pool) *ActivityStore {
	return &ActivityStore{db: pool}
}

// NewActivityStoreWithDB creates an activity store with a custom DBTX implementation.
// This is primarily used for testing with pgxmock.
func NewActivityStoreWithDB(db DBTX) *ActivityStore {
	return &ActivityStore{db: db}
}

// Activity represents an activity record from the database
type Activity struct {
	ID        string
	UserID    string
	Type      string
	DraftID   *string
	PostID    *string
	Platform  *string
	Message   *string
	CreatedAt time.Time
}

// CreateActivity creates a new activity record
func (s *ActivityStore) CreateActivity(ctx context.Context, userID, activityType string, draftID, postID, platform, message *string) (*Activity, error) {
	if !validActivityTypes[activityType] {
		return nil, ErrInvalidActivity
	}

	var activity Activity
	err := s.db.QueryRow(ctx,
		`INSERT INTO activities (user_id, type, draft_id, post_id, platform, message)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, user_id, type, draft_id, post_id, platform, message, created_at`,
		userID, activityType, draftID, postID, platform, message,
	).Scan(&activity.ID, &activity.UserID, &activity.Type, &activity.DraftID, &activity.PostID, &activity.Platform, &activity.Message, &activity.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &activity, nil
}

// GetActivityByID retrieves an activity by its ID
func (s *ActivityStore) GetActivityByID(ctx context.Context, activityID string) (*Activity, error) {
	var activity Activity
	err := s.db.QueryRow(ctx,
		`SELECT id, user_id, type, draft_id, post_id, platform, message, created_at
		 FROM activities
		 WHERE id = $1`,
		activityID,
	).Scan(&activity.ID, &activity.UserID, &activity.Type, &activity.DraftID, &activity.PostID, &activity.Platform, &activity.Message, &activity.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &activity, nil
}

// ListActivitiesByUser retrieves activities for a user with pagination (for dashboard)
// Returns activities in newest-first order
func (s *ActivityStore) ListActivitiesByUser(ctx context.Context, userID string, limit, offset int) ([]*web.DashboardActivity, error) {
	if limit <= 0 {
		limit = 20 // Default limit
	}
	if limit > 100 {
		limit = 100 // Max limit
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := s.db.Query(ctx,
		`SELECT id, type, draft_id, post_id, platform, message, created_at
		 FROM activities
		 WHERE user_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2 OFFSET $3`,
		userID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var activities []*web.DashboardActivity
	for rows.Next() {
		var a web.DashboardActivity
		var createdAt time.Time
		if err := rows.Scan(&a.ID, &a.Type, &a.DraftID, &a.PostID, &a.Platform, &a.Message, &createdAt); err != nil {
			return nil, err
		}
		a.CreatedAt = createdAt
		activities = append(activities, &a)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return activities, nil
}

// CountActivitiesByUser returns the total number of activities for a user
func (s *ActivityStore) CountActivitiesByUser(ctx context.Context, userID string) (int, error) {
	var count int
	err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM activities WHERE user_id = $1`,
		userID,
	).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}
