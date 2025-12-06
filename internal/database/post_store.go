package database

import (
	"context"

	"github.com/mikelady/roxas/internal/web"
)

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
