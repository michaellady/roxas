package database

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mikelady/roxas/internal/web"
)

// Post-related errors
var (
	ErrPostNotFound  = errors.New("post not found")
	ErrInvalidStatus = errors.New("invalid status")
)

// Valid post statuses (must match DB check constraint)
var validPostStatuses = map[string]bool{
	"draft":  true,
	"posted": true,
	"failed": true,
}

// Compile-time interface compliance check
var _ web.PostLister = (*PostStore)(nil)

// PostStore implements web.PostLister using PostgreSQL
type PostStore struct {
	pool *Pool
}

// NewPostStore creates a new database-backed post store
func NewPostStore(pool *Pool) *PostStore {
	return &PostStore{pool: pool}
}

// ListPostsByUser retrieves all posts for a user's commits (for dashboard)
func (s *PostStore) ListPostsByUser(ctx context.Context, userID string) ([]*web.DashboardPost, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT p.id, p.platform, p.content, p.status
		 FROM posts p
		 JOIN commits c ON p.commit_id = c.id
		 JOIN repositories r ON c.repository_id = r.id
		 WHERE r.user_id = $1
		 ORDER BY p.created_at DESC
		 LIMIT 50`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []*web.DashboardPost
	for rows.Next() {
		var post web.DashboardPost
		if err := rows.Scan(&post.ID, &post.Platform, &post.Content, &post.Status); err != nil {
			return nil, err
		}
		posts = append(posts, &post)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return posts, nil
}

// UpdatePostStatus updates the status of a post
// Valid statuses: "draft", "posted", "failed"
func (s *PostStore) UpdatePostStatus(ctx context.Context, postID, status string) error {
	// Validate status before hitting DB
	if !validPostStatuses[status] {
		return ErrInvalidStatus
	}

	result, err := s.pool.Exec(ctx,
		`UPDATE posts SET status = $1 WHERE id = $2`,
		status, postID,
	)

	if err != nil {
		// Check for check constraint violation (invalid status)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23514" {
			return ErrInvalidStatus
		}
		return err
	}

	// Check if any row was updated
	if result.RowsAffected() == 0 {
		// Verify post doesn't exist (vs. some other issue)
		var exists bool
		err = s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM posts WHERE id = $1)", postID).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			return ErrPostNotFound
		}
		// Post exists but status didn't change (same value) - this is OK
	}

	return nil
}
