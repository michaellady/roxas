package database

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// AppRepository represents a GitHub App repository record
type AppRepository struct {
	ID             string
	InstallationID int64
	GitHubRepoID   int64
	FullName       string
	HTMLURL        string
	Private        bool
	DefaultBranch  string
	IsActive       bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// AppRepositoryStore implements CRUD for github_app_repositories
type AppRepositoryStore struct {
	db DBTX
}

// NewAppRepositoryStore creates a new database-backed app repository store
func NewAppRepositoryStore(pool *Pool) *AppRepositoryStore {
	return &AppRepositoryStore{db: pool}
}

// NewAppRepositoryStoreWithDB creates an app repository store with a custom DBTX implementation.
// This is primarily used for testing with pgxmock.
func NewAppRepositoryStoreWithDB(db DBTX) *AppRepositoryStore {
	return &AppRepositoryStore{db: db}
}

const appRepoColumns = `id, installation_id, github_repo_id, full_name, html_url, private, default_branch, is_active, created_at, updated_at`

// UpsertAppRepository inserts or updates a GitHub App repository
func (s *AppRepositoryStore) UpsertAppRepository(ctx context.Context, repo *AppRepository) (*AppRepository, error) {
	var result AppRepository
	err := s.db.QueryRow(ctx,
		`INSERT INTO github_app_repositories (installation_id, github_repo_id, full_name, html_url, private, default_branch)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (installation_id, github_repo_id) DO UPDATE SET
		   full_name = EXCLUDED.full_name,
		   html_url = EXCLUDED.html_url,
		   private = EXCLUDED.private,
		   default_branch = EXCLUDED.default_branch,
		   is_active = true
		 RETURNING `+appRepoColumns,
		repo.InstallationID, repo.GitHubRepoID, repo.FullName, repo.HTMLURL, repo.Private, repo.DefaultBranch,
	).Scan(&result.ID, &result.InstallationID, &result.GitHubRepoID, &result.FullName,
		&result.HTMLURL, &result.Private, &result.DefaultBranch, &result.IsActive,
		&result.CreatedAt, &result.UpdatedAt)

	if err != nil {
		return nil, err
	}
	return &result, nil
}

// RemoveAppRepository deactivates a repository (soft delete)
func (s *AppRepositoryStore) RemoveAppRepository(ctx context.Context, installationID, githubRepoID int64) error {
	result, err := s.db.Exec(ctx,
		`UPDATE github_app_repositories SET is_active = false
		 WHERE installation_id = $1 AND github_repo_id = $2`,
		installationID, githubRepoID,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ListByInstallation retrieves all active repositories for an installation
func (s *AppRepositoryStore) ListByInstallation(ctx context.Context, installationID int64) ([]*AppRepository, error) {
	rows, err := s.db.Query(ctx,
		`SELECT `+appRepoColumns+`
		 FROM github_app_repositories
		 WHERE installation_id = $1 AND is_active = true
		 ORDER BY full_name ASC`,
		installationID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repos []*AppRepository
	for rows.Next() {
		var repo AppRepository
		if err := rows.Scan(&repo.ID, &repo.InstallationID, &repo.GitHubRepoID, &repo.FullName,
			&repo.HTMLURL, &repo.Private, &repo.DefaultBranch, &repo.IsActive,
			&repo.CreatedAt, &repo.UpdatedAt); err != nil {
			return nil, err
		}
		repos = append(repos, &repo)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return repos, nil
}

// GetByGitHubRepoID retrieves a repository by its GitHub repo ID
func (s *AppRepositoryStore) GetByGitHubRepoID(ctx context.Context, githubRepoID int64) (*AppRepository, error) {
	var repo AppRepository
	err := s.db.QueryRow(ctx,
		`SELECT `+appRepoColumns+`
		 FROM github_app_repositories
		 WHERE github_repo_id = $1 AND is_active = true`,
		githubRepoID,
	).Scan(&repo.ID, &repo.InstallationID, &repo.GitHubRepoID, &repo.FullName,
		&repo.HTMLURL, &repo.Private, &repo.DefaultBranch, &repo.IsActive,
		&repo.CreatedAt, &repo.UpdatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &repo, nil
}
