package database

import (
	"context"

	"github.com/mikelady/roxas/internal/web"
)

// CommitStore implements web.CommitLister using PostgreSQL
type CommitStore struct {
	pool *Pool
}

// NewCommitStore creates a new database-backed commit store
func NewCommitStore(pool *Pool) *CommitStore {
	return &CommitStore{pool: pool}
}

// ListCommitsByUser retrieves all commits for a user's repositories (for dashboard)
func (s *CommitStore) ListCommitsByUser(ctx context.Context, userID string) ([]*web.DashboardCommit, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT c.id, c.commit_sha, c.commit_message, c.author
		 FROM commits c
		 JOIN repositories r ON c.repository_id = r.id
		 WHERE r.user_id = $1
		 ORDER BY c.timestamp DESC
		 LIMIT 50`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var commits []*web.DashboardCommit
	for rows.Next() {
		var commit web.DashboardCommit
		if err := rows.Scan(&commit.ID, &commit.SHA, &commit.Message, &commit.Author); err != nil {
			return nil, err
		}
		commits = append(commits, &commit)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return commits, nil
}
