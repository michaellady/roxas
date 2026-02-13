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
	db DBTX
}

// NewRepositoryStore creates a new database-backed repository store
func NewRepositoryStore(pool *Pool) *RepositoryStore {
	return &RepositoryStore{db: pool}
}

// NewRepositoryStoreWithDB creates a repository store with a custom DBTX implementation.
// This is primarily used for testing with pgxmock.
func NewRepositoryStoreWithDB(db DBTX) *RepositoryStore {
	return &RepositoryStore{db: db}
}

const repoColumns = `id, user_id, github_url, webhook_secret, name, is_active, created_at, github_repo_id, webhook_id, is_private, github_app_repo_id, webhook_source`

// scanRepo scans a repository row into a handlers.Repository, handling nullable fields.
func scanRepo(scan func(dest ...any) error) (*handlers.Repository, error) {
	var repo handlers.Repository
	var createdAt time.Time
	var name *string

	err := scan(&repo.ID, &repo.UserID, &repo.GitHubURL, &repo.WebhookSecret, &name, &repo.IsActive,
		&createdAt, &repo.GitHubRepoID, &repo.WebhookID, &repo.IsPrivate,
		&repo.GitHubAppRepoID, &repo.WebhookSource)
	if err != nil {
		return nil, err
	}

	if name != nil {
		repo.Name = *name
	}
	repo.CreatedAt = createdAt
	return &repo, nil
}

// CreateRepository creates a new repository in the database
func (s *RepositoryStore) CreateRepository(ctx context.Context, userID, githubURL, webhookSecret string) (*handlers.Repository, error) {
	row := s.db.QueryRow(ctx,
		`INSERT INTO repositories (user_id, github_url, webhook_secret)
		 VALUES ($1, $2, $3)
		 RETURNING `+repoColumns,
		userID, githubURL, webhookSecret,
	)
	repo, err := scanRepo(row.Scan)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, handlers.ErrDuplicateRepository
		}
		return nil, err
	}
	return repo, nil
}

// GetRepositoryByUserAndURL retrieves a repository by user ID and GitHub URL
func (s *RepositoryStore) GetRepositoryByUserAndURL(ctx context.Context, userID, githubURL string) (*handlers.Repository, error) {
	row := s.db.QueryRow(ctx,
		`SELECT `+repoColumns+`
		 FROM repositories
		 WHERE user_id = $1 AND github_url = $2`,
		userID, githubURL,
	)
	repo, err := scanRepo(row.Scan)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return repo, nil
}

// ListRepositoriesByUser retrieves all repositories for a user
func (s *RepositoryStore) ListRepositoriesByUser(ctx context.Context, userID string) ([]*handlers.Repository, error) {
	rows, err := s.db.Query(ctx,
		`SELECT `+repoColumns+`
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
		repo, err := scanRepo(rows.Scan)
		if err != nil {
			return nil, err
		}
		repos = append(repos, repo)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return repos, nil
}

// GetRepositoryByID retrieves a repository by its ID (for webhook handling)
func (s *RepositoryStore) GetRepositoryByID(ctx context.Context, repoID string) (*handlers.Repository, error) {
	row := s.db.QueryRow(ctx,
		`SELECT `+repoColumns+`
		 FROM repositories
		 WHERE id = $1`,
		repoID,
	)
	repo, err := scanRepo(row.Scan)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return repo, nil
}

// UpdateRepository updates a repository's name and active status
func (s *RepositoryStore) UpdateRepository(ctx context.Context, repoID, name string, isActive bool) (*handlers.Repository, error) {
	row := s.db.QueryRow(ctx,
		`UPDATE repositories
		 SET name = $2, is_active = $3
		 WHERE id = $1
		 RETURNING `+repoColumns,
		repoID, name, isActive,
	)
	repo, err := scanRepo(row.Scan)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return repo, nil
}

// UpdateWebhookSecret updates the webhook secret for a repository
func (s *RepositoryStore) UpdateWebhookSecret(ctx context.Context, repoID, newSecret string) error {
	result, err := s.db.Exec(ctx,
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

// GetRepositoryByAppRepoID retrieves a repository by its linked github_app_repo_id
func (s *RepositoryStore) GetRepositoryByAppRepoID(ctx context.Context, appRepoID string) (*handlers.Repository, error) {
	row := s.db.QueryRow(ctx,
		`SELECT `+repoColumns+`
		 FROM repositories
		 WHERE github_app_repo_id = $1`,
		appRepoID,
	)
	repo, err := scanRepo(row.Scan)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return repo, nil
}

// CreateRepositoryFromApp creates a repository linked to a GitHub App repo
func (s *RepositoryStore) CreateRepositoryFromApp(ctx context.Context, userID, githubURL, webhookSecret, appRepoID string) (*handlers.Repository, error) {
	row := s.db.QueryRow(ctx,
		`INSERT INTO repositories (user_id, github_url, webhook_secret, github_app_repo_id, webhook_source)
		 VALUES ($1, $2, $3, $4, 'github_app')
		 RETURNING `+repoColumns,
		userID, githubURL, webhookSecret, appRepoID,
	)
	repo, err := scanRepo(row.Scan)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, handlers.ErrDuplicateRepository
		}
		return nil, err
	}
	return repo, nil
}

// UpdateRepositoryUserID reassigns a repository to a different user.
func (s *RepositoryStore) UpdateRepositoryUserID(ctx context.Context, repoID, userID string) error {
	result, err := s.db.Exec(ctx,
		`UPDATE repositories SET user_id = $1 WHERE id = $2`,
		userID, repoID,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// DeleteRepository removes a repository from the database
func (s *RepositoryStore) DeleteRepository(ctx context.Context, repoID string) error {
	result, err := s.db.Exec(ctx,
		`DELETE FROM repositories WHERE id = $1`,
		repoID,
	)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}

	return nil
}
