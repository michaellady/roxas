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

var appRepoTestColumns = []string{"id", "installation_id", "github_repo_id", "full_name", "html_url", "private", "default_branch", "is_active", "created_at", "updated_at"}

func TestAppRepositoryStore_UpsertAppRepository_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewAppRepositoryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	rows := pgxmock.NewRows(appRepoTestColumns).
		AddRow("ar-1", int64(100), int64(200), "org/repo", "https://github.com/org/repo", false, "main", true, now, now)

	mock.ExpectQuery(`INSERT INTO github_app_repositories`).
		WithArgs(int64(100), int64(200), "org/repo", "https://github.com/org/repo", false, "main").
		WillReturnRows(rows)

	repo, err := store.UpsertAppRepository(context.Background(), &AppRepository{
		InstallationID: 100,
		GitHubRepoID:   200,
		FullName:       "org/repo",
		HTMLURL:        "https://github.com/org/repo",
		Private:        false,
		DefaultBranch:  "main",
	})

	require.NoError(t, err)
	require.NotNil(t, repo)
	assert.Equal(t, "ar-1", repo.ID)
	assert.Equal(t, int64(100), repo.InstallationID)
	assert.Equal(t, int64(200), repo.GitHubRepoID)
	assert.Equal(t, "org/repo", repo.FullName)
	assert.Equal(t, "https://github.com/org/repo", repo.HTMLURL)
	assert.False(t, repo.Private)
	assert.Equal(t, "main", repo.DefaultBranch)
	assert.True(t, repo.IsActive)
	assert.Equal(t, now, repo.CreatedAt)
	assert.Equal(t, now, repo.UpdatedAt)
}

func TestAppRepositoryStore_UpsertAppRepository_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewAppRepositoryStoreWithDB(mock)

	mock.ExpectQuery(`INSERT INTO github_app_repositories`).
		WithArgs(int64(100), int64(200), "org/repo", "https://github.com/org/repo", false, "main").
		WillReturnError(errors.New("db error"))

	repo, err := store.UpsertAppRepository(context.Background(), &AppRepository{
		InstallationID: 100,
		GitHubRepoID:   200,
		FullName:       "org/repo",
		HTMLURL:        "https://github.com/org/repo",
		Private:        false,
		DefaultBranch:  "main",
	})

	assert.Error(t, err)
	assert.Nil(t, repo)
}

func TestAppRepositoryStore_RemoveAppRepository_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewAppRepositoryStoreWithDB(mock)

	mock.ExpectExec(`UPDATE github_app_repositories SET is_active = false`).
		WithArgs(int64(100), int64(200)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := store.RemoveAppRepository(context.Background(), 100, 200)

	assert.NoError(t, err)
}

func TestAppRepositoryStore_RemoveAppRepository_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewAppRepositoryStoreWithDB(mock)

	mock.ExpectExec(`UPDATE github_app_repositories SET is_active = false`).
		WithArgs(int64(100), int64(999)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := store.RemoveAppRepository(context.Background(), 100, 999)

	assert.ErrorIs(t, err, pgx.ErrNoRows)
}

func TestAppRepositoryStore_RemoveAppRepository_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewAppRepositoryStoreWithDB(mock)

	mock.ExpectExec(`UPDATE github_app_repositories SET is_active = false`).
		WithArgs(int64(100), int64(200)).
		WillReturnError(errors.New("db error"))

	err := store.RemoveAppRepository(context.Background(), 100, 200)

	assert.Error(t, err)
}

func TestAppRepositoryStore_ListByInstallation_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewAppRepositoryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	rows := pgxmock.NewRows(appRepoTestColumns).
		AddRow("ar-1", int64(100), int64(200), "org/alpha", "https://github.com/org/alpha", false, "main", true, now, now).
		AddRow("ar-2", int64(100), int64(201), "org/beta", "https://github.com/org/beta", true, "develop", true, now, now)

	mock.ExpectQuery(`SELECT id, installation_id, github_repo_id`).
		WithArgs(int64(100)).
		WillReturnRows(rows)

	repos, err := store.ListByInstallation(context.Background(), 100)

	require.NoError(t, err)
	require.Len(t, repos, 2)
	assert.Equal(t, "ar-1", repos[0].ID)
	assert.Equal(t, "org/alpha", repos[0].FullName)
	assert.False(t, repos[0].Private)
	assert.Equal(t, "main", repos[0].DefaultBranch)
	assert.Equal(t, "ar-2", repos[1].ID)
	assert.Equal(t, "org/beta", repos[1].FullName)
	assert.True(t, repos[1].Private)
	assert.Equal(t, "develop", repos[1].DefaultBranch)
}

func TestAppRepositoryStore_ListByInstallation_Empty(t *testing.T) {
	mock := NewMockPool(t)
	store := NewAppRepositoryStoreWithDB(mock)

	rows := pgxmock.NewRows(appRepoTestColumns)

	mock.ExpectQuery(`SELECT id, installation_id, github_repo_id`).
		WithArgs(int64(999)).
		WillReturnRows(rows)

	repos, err := store.ListByInstallation(context.Background(), 999)

	require.NoError(t, err)
	assert.Empty(t, repos)
}

func TestAppRepositoryStore_ListByInstallation_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewAppRepositoryStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, installation_id, github_repo_id`).
		WithArgs(int64(100)).
		WillReturnError(errors.New("query error"))

	repos, err := store.ListByInstallation(context.Background(), 100)

	assert.Error(t, err)
	assert.Nil(t, repos)
}

func TestAppRepositoryStore_GetByGitHubRepoID_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewAppRepositoryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	rows := pgxmock.NewRows(appRepoTestColumns).
		AddRow("ar-1", int64(100), int64(200), "org/repo", "https://github.com/org/repo", false, "main", true, now, now)

	mock.ExpectQuery(`SELECT id, installation_id, github_repo_id`).
		WithArgs(int64(200)).
		WillReturnRows(rows)

	repo, err := store.GetByGitHubRepoID(context.Background(), 200)

	require.NoError(t, err)
	require.NotNil(t, repo)
	assert.Equal(t, "ar-1", repo.ID)
	assert.Equal(t, int64(100), repo.InstallationID)
	assert.Equal(t, int64(200), repo.GitHubRepoID)
	assert.Equal(t, "org/repo", repo.FullName)
	assert.Equal(t, "https://github.com/org/repo", repo.HTMLURL)
	assert.False(t, repo.Private)
	assert.Equal(t, "main", repo.DefaultBranch)
	assert.True(t, repo.IsActive)
	assert.Equal(t, now, repo.CreatedAt)
	assert.Equal(t, now, repo.UpdatedAt)
}

func TestAppRepositoryStore_GetByGitHubRepoID_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewAppRepositoryStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, installation_id, github_repo_id`).
		WithArgs(int64(999)).
		WillReturnError(pgx.ErrNoRows)

	repo, err := store.GetByGitHubRepoID(context.Background(), 999)

	assert.NoError(t, err)
	assert.Nil(t, repo)
}

func TestAppRepositoryStore_GetByGitHubRepoID_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewAppRepositoryStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, installation_id, github_repo_id`).
		WithArgs(int64(200)).
		WillReturnError(errors.New("db error"))

	repo, err := store.GetByGitHubRepoID(context.Background(), 200)

	assert.Error(t, err)
	assert.Nil(t, repo)
}
