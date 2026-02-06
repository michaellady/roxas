package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mikelady/roxas/internal/handlers"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var repoColumns = []string{"id", "user_id", "github_url", "webhook_secret", "name", "is_active", "created_at", "github_repo_id", "webhook_id", "is_private"}

func TestRepositoryStore_NewRepositoryStoreWithDB(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)
	require.NotNil(t, store)
}

func TestRepositoryStore_CreateRepository_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	repoName := "test-repo"
	rows := pgxmock.NewRows(repoColumns).
		AddRow("repo-1", "user-1", "https://github.com/test/repo", "secret123", &repoName, true, now, nil, nil, false)

	mock.ExpectQuery(`INSERT INTO repositories`).
		WithArgs("user-1", "https://github.com/test/repo", "secret123").
		WillReturnRows(rows)

	repo, err := store.CreateRepository(context.Background(), "user-1", "https://github.com/test/repo", "secret123")

	require.NoError(t, err)
	require.NotNil(t, repo)
	assert.Equal(t, "repo-1", repo.ID)
	assert.Equal(t, "user-1", repo.UserID)
	assert.Equal(t, "https://github.com/test/repo", repo.GitHubURL)
	assert.Equal(t, "test-repo", repo.Name)
	assert.True(t, repo.IsActive)
	assert.Equal(t, now, repo.CreatedAt)
}

func TestRepositoryStore_CreateRepository_NilName(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	rows := pgxmock.NewRows(repoColumns).
		AddRow("repo-1", "user-1", "https://github.com/test/repo", "secret123", nil, true, now, nil, nil, false)

	mock.ExpectQuery(`INSERT INTO repositories`).
		WithArgs("user-1", "https://github.com/test/repo", "secret123").
		WillReturnRows(rows)

	repo, err := store.CreateRepository(context.Background(), "user-1", "https://github.com/test/repo", "secret123")

	require.NoError(t, err)
	require.NotNil(t, repo)
	assert.Equal(t, "", repo.Name)
}

func TestRepositoryStore_CreateRepository_Duplicate(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	pgErr := &pgconn.PgError{Code: "23505"}
	mock.ExpectQuery(`INSERT INTO repositories`).
		WithArgs("user-1", "https://github.com/test/repo", "secret123").
		WillReturnError(pgErr)

	repo, err := store.CreateRepository(context.Background(), "user-1", "https://github.com/test/repo", "secret123")

	assert.ErrorIs(t, err, handlers.ErrDuplicateRepository)
	assert.Nil(t, repo)
}

func TestRepositoryStore_CreateRepository_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectQuery(`INSERT INTO repositories`).
		WithArgs("user-1", "https://github.com/test/repo", "secret123").
		WillReturnError(errors.New("db error"))

	repo, err := store.CreateRepository(context.Background(), "user-1", "https://github.com/test/repo", "secret123")

	assert.Error(t, err)
	assert.Nil(t, repo)
}

func TestRepositoryStore_GetRepositoryByUserAndURL_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	name := "my-repo"
	rows := pgxmock.NewRows(repoColumns).
		AddRow("repo-1", "user-1", "https://github.com/test/repo", "secret", &name, true, now, nil, nil, false)

	mock.ExpectQuery(`SELECT id, user_id, github_url`).
		WithArgs("user-1", "https://github.com/test/repo").
		WillReturnRows(rows)

	repo, err := store.GetRepositoryByUserAndURL(context.Background(), "user-1", "https://github.com/test/repo")

	require.NoError(t, err)
	require.NotNil(t, repo)
	assert.Equal(t, "repo-1", repo.ID)
	assert.Equal(t, "my-repo", repo.Name)
}

func TestRepositoryStore_GetRepositoryByUserAndURL_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, user_id, github_url`).
		WithArgs("user-1", "https://github.com/test/nope").
		WillReturnError(pgx.ErrNoRows)

	repo, err := store.GetRepositoryByUserAndURL(context.Background(), "user-1", "https://github.com/test/nope")

	assert.NoError(t, err)
	assert.Nil(t, repo)
}

func TestRepositoryStore_GetRepositoryByUserAndURL_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, user_id, github_url`).
		WithArgs("user-1", "https://github.com/test/repo").
		WillReturnError(errors.New("db error"))

	repo, err := store.GetRepositoryByUserAndURL(context.Background(), "user-1", "https://github.com/test/repo")

	assert.Error(t, err)
	assert.Nil(t, repo)
}

func TestRepositoryStore_ListRepositoriesByUser_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	name1 := "repo-one"
	name2 := "repo-two"
	rows := pgxmock.NewRows(repoColumns).
		AddRow("repo-1", "user-1", "https://github.com/test/one", "s1", &name1, true, now, nil, nil, false).
		AddRow("repo-2", "user-1", "https://github.com/test/two", "s2", &name2, false, now, nil, nil, true)

	mock.ExpectQuery(`SELECT id, user_id, github_url`).
		WithArgs("user-1").
		WillReturnRows(rows)

	repos, err := store.ListRepositoriesByUser(context.Background(), "user-1")

	require.NoError(t, err)
	require.Len(t, repos, 2)
	assert.Equal(t, "repo-1", repos[0].ID)
	assert.Equal(t, "repo-one", repos[0].Name)
	assert.True(t, repos[0].IsActive)
	assert.Equal(t, "repo-2", repos[1].ID)
	assert.False(t, repos[1].IsActive)
	assert.True(t, repos[1].IsPrivate)
}

func TestRepositoryStore_ListRepositoriesByUser_Empty(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	rows := pgxmock.NewRows(repoColumns)

	mock.ExpectQuery(`SELECT id, user_id, github_url`).
		WithArgs("user-none").
		WillReturnRows(rows)

	repos, err := store.ListRepositoriesByUser(context.Background(), "user-none")

	require.NoError(t, err)
	assert.Empty(t, repos)
}

func TestRepositoryStore_ListRepositoriesByUser_QueryError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, user_id, github_url`).
		WithArgs("user-1").
		WillReturnError(errors.New("query error"))

	repos, err := store.ListRepositoriesByUser(context.Background(), "user-1")

	assert.Error(t, err)
	assert.Nil(t, repos)
}

func TestRepositoryStore_ListRepositoriesByUser_ScanError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	rows := pgxmock.NewRows(repoColumns).
		AddRow("repo-1", "user-1", "url", "s", nil, true, time.Now(), nil, nil, false).
		RowError(0, errors.New("scan error"))

	mock.ExpectQuery(`SELECT id, user_id, github_url`).
		WithArgs("user-1").
		WillReturnRows(rows)

	repos, err := store.ListRepositoriesByUser(context.Background(), "user-1")

	assert.Error(t, err)
	assert.Nil(t, repos)
}

func TestRepositoryStore_GetRepositoryByID_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	name := "test-repo"
	rows := pgxmock.NewRows(repoColumns).
		AddRow("repo-1", "user-1", "https://github.com/test/repo", "secret", &name, true, now, nil, nil, false)

	mock.ExpectQuery(`SELECT id, user_id, github_url`).
		WithArgs("repo-1").
		WillReturnRows(rows)

	repo, err := store.GetRepositoryByID(context.Background(), "repo-1")

	require.NoError(t, err)
	require.NotNil(t, repo)
	assert.Equal(t, "repo-1", repo.ID)
}

func TestRepositoryStore_GetRepositoryByID_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, user_id, github_url`).
		WithArgs("nonexistent").
		WillReturnError(pgx.ErrNoRows)

	repo, err := store.GetRepositoryByID(context.Background(), "nonexistent")

	assert.NoError(t, err)
	assert.Nil(t, repo)
}

func TestRepositoryStore_GetRepositoryByID_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, user_id, github_url`).
		WithArgs("repo-1").
		WillReturnError(errors.New("db error"))

	repo, err := store.GetRepositoryByID(context.Background(), "repo-1")

	assert.Error(t, err)
	assert.Nil(t, repo)
}

func TestRepositoryStore_UpdateRepository_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	name := "updated-name"
	rows := pgxmock.NewRows(repoColumns).
		AddRow("repo-1", "user-1", "https://github.com/test/repo", "secret", &name, true, now, nil, nil, false)

	mock.ExpectQuery(`UPDATE repositories`).
		WithArgs("repo-1", "updated-name", true).
		WillReturnRows(rows)

	repo, err := store.UpdateRepository(context.Background(), "repo-1", "updated-name", true)

	require.NoError(t, err)
	require.NotNil(t, repo)
	assert.Equal(t, "updated-name", repo.Name)
	assert.True(t, repo.IsActive)
}

func TestRepositoryStore_UpdateRepository_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectQuery(`UPDATE repositories`).
		WithArgs("nonexistent", "name", true).
		WillReturnError(pgx.ErrNoRows)

	repo, err := store.UpdateRepository(context.Background(), "nonexistent", "name", true)

	assert.NoError(t, err)
	assert.Nil(t, repo)
}

func TestRepositoryStore_UpdateRepository_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectQuery(`UPDATE repositories`).
		WithArgs("repo-1", "name", true).
		WillReturnError(errors.New("db error"))

	repo, err := store.UpdateRepository(context.Background(), "repo-1", "name", true)

	assert.Error(t, err)
	assert.Nil(t, repo)
}

func TestRepositoryStore_UpdateWebhookSecret_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectExec(`UPDATE repositories SET webhook_secret`).
		WithArgs("new-secret", "repo-1").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := store.UpdateWebhookSecret(context.Background(), "repo-1", "new-secret")

	assert.NoError(t, err)
}

func TestRepositoryStore_UpdateWebhookSecret_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectExec(`UPDATE repositories SET webhook_secret`).
		WithArgs("new-secret", "nonexistent").
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := store.UpdateWebhookSecret(context.Background(), "nonexistent", "new-secret")

	assert.ErrorIs(t, err, pgx.ErrNoRows)
}

func TestRepositoryStore_UpdateWebhookSecret_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectExec(`UPDATE repositories SET webhook_secret`).
		WithArgs("new-secret", "repo-1").
		WillReturnError(errors.New("db error"))

	err := store.UpdateWebhookSecret(context.Background(), "repo-1", "new-secret")

	assert.Error(t, err)
}

func TestRepositoryStore_DeleteRepository_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectExec(`DELETE FROM repositories WHERE id`).
		WithArgs("repo-1").
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	err := store.DeleteRepository(context.Background(), "repo-1")

	assert.NoError(t, err)
}

func TestRepositoryStore_DeleteRepository_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectExec(`DELETE FROM repositories WHERE id`).
		WithArgs("nonexistent").
		WillReturnResult(pgxmock.NewResult("DELETE", 0))

	err := store.DeleteRepository(context.Background(), "nonexistent")

	assert.ErrorIs(t, err, pgx.ErrNoRows)
}

func TestRepositoryStore_DeleteRepository_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewRepositoryStoreWithDB(mock)

	mock.ExpectExec(`DELETE FROM repositories WHERE id`).
		WithArgs("repo-1").
		WillReturnError(errors.New("db error"))

	err := store.DeleteRepository(context.Background(), "repo-1")

	assert.Error(t, err)
}
