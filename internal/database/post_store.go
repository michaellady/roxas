package database

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mikelady/roxas/internal/handlers"
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

// Compile-time interface compliance checks
var (
	_ web.PostLister     = (*PostStore)(nil)
	_ handlers.PostStore = (*PostStore)(nil)
	_ web.DraftCounter   = (*PostStore)(nil)
)

// PostStore implements web.PostLister using PostgreSQL
type PostStore struct {
	pool *Pool
}

// NewPostStore creates a new database-backed post store
func NewPostStore(pool *Pool) *PostStore {
	return &PostStore{pool: pool}
}

// CreatePost creates a new post in the database with status 'draft'
func (s *PostStore) CreatePost(ctx context.Context, commitID, platform, content string) (*handlers.Post, error) {
	var post handlers.Post
	var createdAt time.Time

	err := s.pool.QueryRow(ctx,
		`INSERT INTO posts (commit_id, platform, content, status)
		 VALUES ($1, $2, $3, 'draft')
		 RETURNING id, commit_id, platform, content, status, created_at`,
		commitID, platform, content,
	).Scan(&post.ID, &post.CommitID, &post.Platform, &post.Content, &post.Status, &createdAt)

	if err != nil {
		// Check for unique constraint violation (duplicate commit_id + platform + version)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, handlers.ErrDuplicatePost
		}
		return nil, err
	}

	post.CreatedAt = createdAt
	return &post, nil
}

// GetPostByID retrieves a post by its ID
func (s *PostStore) GetPostByID(ctx context.Context, postID string) (*handlers.Post, error) {
	var post handlers.Post
	var createdAt time.Time

	err := s.pool.QueryRow(ctx,
		`SELECT id, commit_id, platform, content, status, created_at
		 FROM posts
		 WHERE id = $1`,
		postID,
	).Scan(&post.ID, &post.CommitID, &post.Platform, &post.Content, &post.Status, &createdAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	post.CreatedAt = createdAt
	return &post, nil
}

// GetPostsByUserID retrieves all posts for a user (via their commits)
func (s *PostStore) GetPostsByUserID(ctx context.Context, userID string) ([]*handlers.Post, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT p.id, p.commit_id, p.platform, p.content, p.status, p.created_at
		 FROM posts p
		 JOIN commits c ON p.commit_id = c.id
		 JOIN repositories r ON c.repository_id = r.id
		 WHERE r.user_id = $1
		 ORDER BY p.created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []*handlers.Post
	for rows.Next() {
		var post handlers.Post
		var createdAt time.Time
		if err := rows.Scan(&post.ID, &post.CommitID, &post.Platform, &post.Content, &post.Status, &createdAt); err != nil {
			return nil, err
		}
		post.CreatedAt = createdAt
		posts = append(posts, &post)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return posts, nil
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

// CountDraftsByUser returns the number of draft posts for a user
func (s *PostStore) CountDraftsByUser(ctx context.Context, userID string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*)
		 FROM posts p
		 JOIN commits c ON p.commit_id = c.id
		 JOIN repositories r ON c.repository_id = r.id
		 WHERE r.user_id = $1 AND p.status = 'draft'`,
		userID,
	).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}
