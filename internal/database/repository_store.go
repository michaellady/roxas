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

// Compile-time interface compliance checks
var (
	_ handlers.RepositoryStore = (*RepositoryStore)(nil)
	_ web.RepositoryStore      = (*RepositoryStore)(nil)
)

// RepositoryStore implements handlers.RepositoryStore using PostgreSQL
type RepositoryStore struct {
	pool *Pool
}

// NewRepositoryStore creates a new database-backed repository store
func NewRepositoryStore(pool *Pool) *RepositoryStore {
	return &RepositoryStore{pool: pool}
}

// CreateRepository creates a new repository in the database
func (s *RepositoryStore) CreateRepository(ctx context.Context, userID, githubURL, webhookSecret string) (*handlers.Repository, error) {
	var repo handlers.Repository
	var createdAt time.Time
	var name *string

	err := s.pool.QueryRow(ctx,
		`INSERT INTO repositories (user_id, github_url, webhook_secret)
		 VALUES ($1, $2, $3)
		 RETURNING id, user_id, github_url, webhook_secret, name, is_active, created_at`,
		userID, githubURL, webhookSecret,
	).Scan(&repo.ID, &repo.UserID, &repo.GitHubURL, &repo.WebhookSecret, &name, &repo.IsActive, &createdAt)

	if err != nil {
		// Check for unique constraint violation (duplicate repo for user)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, handlers.ErrDuplicateRepository
		}
		return nil, err
	}

	if name != nil {
		repo.Name = *name
	}
	repo.CreatedAt = createdAt
	return &repo, nil
}

// GetRepositoryByUserAndURL retrieves a repository by user ID and GitHub URL
func (s *RepositoryStore) GetRepositoryByUserAndURL(ctx context.Context, userID, githubURL string) (*handlers.Repository, error) {
	var repo handlers.Repository
	var createdAt time.Time
	var name *string

	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, github_url, webhook_secret, name, is_active, created_at
		 FROM repositories
		 WHERE user_id = $1 AND github_url = $2`,
		userID, githubURL,
	).Scan(&repo.ID, &repo.UserID, &repo.GitHubURL, &repo.WebhookSecret, &name, &repo.IsActive, &createdAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if name != nil {
		repo.Name = *name
	}
	repo.CreatedAt = createdAt
	return &repo, nil
}

// ListRepositoriesByUser retrieves all repositories for a user
func (s *RepositoryStore) ListRepositoriesByUser(ctx context.Context, userID string) ([]*handlers.Repository, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, github_url, webhook_secret, name, is_active, created_at
		 FROM repositories
		 WHERE user_id = $1
		 ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repos []*handlers.Repository
	for rows.Next() {
		var repo handlers.Repository
		var createdAt time.Time
		var name *string
		if err := rows.Scan(&repo.ID, &repo.UserID, &repo.GitHubURL, &repo.WebhookSecret, &name, &repo.IsActive, &createdAt); err != nil {
			return nil, err
		}
		if name != nil {
			repo.Name = *name
		}
		repo.CreatedAt = createdAt
		repos = append(repos, &repo)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return repos, nil
}

// GetRepositoryByID retrieves a repository by its ID (for webhook handling)
func (s *RepositoryStore) GetRepositoryByID(ctx context.Context, repoID string) (*handlers.Repository, error) {
	var repo handlers.Repository
	var createdAt time.Time
	var name *string

	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, github_url, webhook_secret, name, is_active, created_at
		 FROM repositories
		 WHERE id = $1`,
		repoID,
	).Scan(&repo.ID, &repo.UserID, &repo.GitHubURL, &repo.WebhookSecret, &name, &repo.IsActive, &createdAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if name != nil {
		repo.Name = *name
	}
	repo.CreatedAt = createdAt
	return &repo, nil
}

// UpdateRepository updates a repository's name and active status
func (s *RepositoryStore) UpdateRepository(ctx context.Context, repoID, name string, isActive bool) (*handlers.Repository, error) {
	var repo handlers.Repository
	var createdAt time.Time
	var namePtr *string

	err := s.pool.QueryRow(ctx,
		`UPDATE repositories
		 SET name = $2, is_active = $3
		 WHERE id = $1
		 RETURNING id, user_id, github_url, webhook_secret, name, is_active, created_at`,
		repoID, name, isActive,
	).Scan(&repo.ID, &repo.UserID, &repo.GitHubURL, &repo.WebhookSecret, &namePtr, &repo.IsActive, &createdAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if namePtr != nil {
		repo.Name = *namePtr
	}
	repo.CreatedAt = createdAt
	return &repo, nil
}

// UpdateWebhookSecret updates the webhook secret for a repository
func (s *RepositoryStore) UpdateWebhookSecret(ctx context.Context, repoID, newSecret string) error {
	result, err := s.pool.Exec(ctx,
		`UPDATE repositories SET webhook_secret = $1 WHERE id = $2`,
		newSecret, repoID,
	)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}

	return nil
}
