package database

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var draftColumns = []string{"id", "user_id", "repository_id", "ref", "before_sha", "after_sha", "commit_shas", "generated_content", "edited_content", "status", "created_at", "updated_at"}

func TestDraftStore_NewDraftStoreWithDB(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)
	require.NotNil(t, store)
}

func TestDraftStore_CreateDraft_Mock_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	commitSHAs := []string{"abc123", "def456"}
	commitSHAsJSON, _ := json.Marshal(commitSHAs)

	rows := pgxmock.NewRows(draftColumns).
		AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "before1", "after1", commitSHAsJSON, "Generated content", nil, "draft", now, now)

	mock.ExpectQuery(`INSERT INTO drafts`).
		WithArgs("user-1", "repo-1", "refs/heads/main", "before1", "after1", pgxmock.AnyArg(), 2, "Generated content").
		WillReturnRows(rows)

	draft, err := store.CreateDraft(context.Background(), "user-1", "repo-1", "refs/heads/main", "before1", "after1", commitSHAs, "Generated content")

	require.NoError(t, err)
	require.NotNil(t, draft)
	assert.Equal(t, "draft-1", draft.ID)
	assert.Equal(t, "user-1", draft.UserID)
	assert.Equal(t, "repo-1", draft.RepositoryID)
	assert.Equal(t, "refs/heads/main", draft.Ref)
	assert.Equal(t, "draft", draft.Status)
	assert.Equal(t, commitSHAs, draft.CommitSHAs)
}

func TestDraftStore_CreateDraft_Mock_EmptyUserID(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	draft, err := store.CreateDraft(context.Background(), "", "repo-1", "refs/heads/main", "b", "a", []string{"a"}, "content")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user_id")
	assert.Nil(t, draft)
}

func TestDraftStore_CreateDraft_Mock_EmptyRepoID(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	draft, err := store.CreateDraft(context.Background(), "user-1", "", "refs/heads/main", "b", "a", []string{"a"}, "content")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "repository_id")
	assert.Nil(t, draft)
}

func TestDraftStore_CreateDraft_Mock_EmptyAfterSHA(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	draft, err := store.CreateDraft(context.Background(), "user-1", "repo-1", "refs/heads/main", "b", "", []string{"a"}, "content")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "after_sha")
	assert.Nil(t, draft)
}

func TestDraftStore_CreateDraft_Mock_EmptyRef(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	draft, err := store.CreateDraft(context.Background(), "user-1", "repo-1", "", "b", "a", []string{"a"}, "content")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ref")
	assert.Nil(t, draft)
}

func TestDraftStore_CreateDraft_Mock_EmptyCommitSHAs(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	emptyJSON, _ := json.Marshal([]string{})

	rows := pgxmock.NewRows(draftColumns).
		AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "b", "a", emptyJSON, "content", nil, "draft", now, now)

	mock.ExpectQuery(`INSERT INTO drafts`).
		WithArgs("user-1", "repo-1", "refs/heads/main", "b", "a", pgxmock.AnyArg(), 1, "content").
		WillReturnRows(rows)

	draft, err := store.CreateDraft(context.Background(), "user-1", "repo-1", "refs/heads/main", "b", "a", []string{}, "content")

	require.NoError(t, err)
	require.NotNil(t, draft)
}

func TestDraftStore_CreateDraft_Mock_UniqueViolation(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	pgErr := &pgconn.PgError{Code: "23505"}
	mock.ExpectQuery(`INSERT INTO drafts`).
		WithArgs("user-1", "repo-1", "refs/heads/main", "b", "a", pgxmock.AnyArg(), 1, "content").
		WillReturnError(pgErr)

	draft, err := store.CreateDraft(context.Background(), "user-1", "repo-1", "refs/heads/main", "b", "a", []string{"a"}, "content")

	assert.ErrorIs(t, err, ErrDuplicateDraft)
	assert.Nil(t, draft)
}

func TestDraftStore_CreateDraft_Mock_ForeignKeyViolation(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	pgErr := &pgconn.PgError{Code: "23503"}
	mock.ExpectQuery(`INSERT INTO drafts`).
		WithArgs("user-1", "repo-1", "refs/heads/main", "b", "a", pgxmock.AnyArg(), 1, "content").
		WillReturnError(pgErr)

	draft, err := store.CreateDraft(context.Background(), "user-1", "repo-1", "refs/heads/main", "b", "a", []string{"a"}, "content")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "foreign key")
	assert.Nil(t, draft)
}

func TestDraftStore_CreateDraft_Mock_DatabaseError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectQuery(`INSERT INTO drafts`).
		WithArgs("user-1", "repo-1", "refs/heads/main", "b", "a", pgxmock.AnyArg(), 1, "content").
		WillReturnError(errors.New("db error"))

	draft, err := store.CreateDraft(context.Background(), "user-1", "repo-1", "refs/heads/main", "b", "a", []string{"a"}, "content")

	assert.Error(t, err)
	assert.Nil(t, draft)
}

func TestDraftStore_GetDraft_Mock_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	commitSHAs := []string{"abc123"}
	commitSHAsJSON, _ := json.Marshal(commitSHAs)

	rows := pgxmock.NewRows(draftColumns).
		AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "before", "after", commitSHAsJSON, "content", nil, "draft", now, now)

	mock.ExpectQuery(`SELECT id, user_id, repository_id, ref`).
		WithArgs("draft-1").
		WillReturnRows(rows)

	draft, err := store.GetDraft(context.Background(), "draft-1")

	require.NoError(t, err)
	require.NotNil(t, draft)
	assert.Equal(t, "draft-1", draft.ID)
	assert.Equal(t, "user-1", draft.UserID)
	assert.Equal(t, commitSHAs, draft.CommitSHAs)
}

func TestDraftStore_GetDraft_Mock_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, user_id, repository_id`).
		WithArgs("nonexistent").
		WillReturnError(pgx.ErrNoRows)

	draft, err := store.GetDraft(context.Background(), "nonexistent")

	assert.ErrorIs(t, err, ErrDraftNotFound)
	assert.Nil(t, draft)
}

func TestDraftStore_GetDraft_Mock_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, user_id, repository_id`).
		WithArgs("draft-1").
		WillReturnError(errors.New("db error"))

	draft, err := store.GetDraft(context.Background(), "draft-1")

	assert.Error(t, err)
	assert.Nil(t, draft)
}

func TestDraftStore_ListDraftsByUser_Mock_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	sha1, _ := json.Marshal([]string{"a1"})
	sha2, _ := json.Marshal([]string{"a2"})

	rows := pgxmock.NewRows(draftColumns).
		AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "b1", "a1", sha1, "content1", nil, "draft", now, now).
		AddRow("draft-2", "user-1", "repo-1", "refs/heads/dev", "b2", "a2", sha2, "content2", nil, "posted", now, now)

	mock.ExpectQuery(`SELECT id, user_id, repository_id`).
		WithArgs("user-1").
		WillReturnRows(rows)

	drafts, err := store.ListDraftsByUser(context.Background(), "user-1")

	require.NoError(t, err)
	require.Len(t, drafts, 2)
	assert.Equal(t, "draft-1", drafts[0].ID)
	assert.Equal(t, "draft-2", drafts[1].ID)
}

func TestDraftStore_ListDraftsByUser_Mock_Empty(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	rows := pgxmock.NewRows(draftColumns)

	mock.ExpectQuery(`SELECT id, user_id, repository_id`).
		WithArgs("user-1").
		WillReturnRows(rows)

	drafts, err := store.ListDraftsByUser(context.Background(), "user-1")

	require.NoError(t, err)
	assert.Empty(t, drafts)
}

func TestDraftStore_ListDraftsByUser_Mock_QueryError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, user_id, repository_id`).
		WithArgs("user-1").
		WillReturnError(errors.New("query error"))

	drafts, err := store.ListDraftsByUser(context.Background(), "user-1")

	assert.Error(t, err)
	assert.Nil(t, drafts)
}

func TestDraftStore_ListDraftsByUser_Mock_ScanError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	sha1, _ := json.Marshal([]string{"a1"})
	rows := pgxmock.NewRows(draftColumns).
		AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "b1", "a1", sha1, "content", nil, "draft", time.Now(), time.Now()).
		RowError(0, errors.New("scan error"))

	mock.ExpectQuery(`SELECT id, user_id, repository_id`).
		WithArgs("user-1").
		WillReturnRows(rows)

	drafts, err := store.ListDraftsByUser(context.Background(), "user-1")

	assert.Error(t, err)
	assert.Nil(t, drafts)
}

func TestDraftStore_UpdateDraftContent_Mock_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectExec(`UPDATE drafts SET edited_content`).
		WithArgs("new content", "draft-1").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := store.UpdateDraftContent(context.Background(), "draft-1", "new content")

	assert.NoError(t, err)
}

func TestDraftStore_UpdateDraftContent_Mock_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectExec(`UPDATE drafts SET edited_content`).
		WithArgs("content", "nonexistent").
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := store.UpdateDraftContent(context.Background(), "nonexistent", "content")

	assert.ErrorIs(t, err, ErrDraftNotFound)
}

func TestDraftStore_UpdateDraftContent_Mock_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectExec(`UPDATE drafts SET edited_content`).
		WithArgs("content", "draft-1").
		WillReturnError(errors.New("db error"))

	err := store.UpdateDraftContent(context.Background(), "draft-1", "content")

	assert.Error(t, err)
}

func TestDraftStore_UpdateDraftStatus_Mock_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectExec(`UPDATE drafts SET status`).
		WithArgs("posted", "draft-1").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := store.UpdateDraftStatus(context.Background(), "draft-1", "posted")

	assert.NoError(t, err)
}

func TestDraftStore_UpdateDraftStatus_Mock_InvalidStatus(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	err := store.UpdateDraftStatus(context.Background(), "draft-1", "invalid_status")

	assert.ErrorIs(t, err, ErrInvalidDraftStatus)
}

func TestDraftStore_UpdateDraftStatus_Mock_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectExec(`UPDATE drafts SET status`).
		WithArgs("posted", "nonexistent").
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := store.UpdateDraftStatus(context.Background(), "nonexistent", "posted")

	assert.ErrorIs(t, err, ErrDraftNotFound)
}

func TestDraftStore_UpdateDraftStatus_Mock_CheckConstraintViolation(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	pgErr := &pgconn.PgError{Code: "23514"}
	mock.ExpectExec(`UPDATE drafts SET status`).
		WithArgs("partial", "draft-1").
		WillReturnError(pgErr)

	err := store.UpdateDraftStatus(context.Background(), "draft-1", "partial")

	assert.ErrorIs(t, err, ErrInvalidDraftStatus)
}

func TestDraftStore_UpdateDraftStatus_Mock_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectExec(`UPDATE drafts SET status`).
		WithArgs("posted", "draft-1").
		WillReturnError(errors.New("db error"))

	err := store.UpdateDraftStatus(context.Background(), "draft-1", "posted")

	assert.Error(t, err)
}

func TestDraftStore_DeleteDraft_Mock_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectExec(`DELETE FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	err := store.DeleteDraft(context.Background(), "draft-1")

	assert.NoError(t, err)
}

func TestDraftStore_DeleteDraft_Mock_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectExec(`DELETE FROM drafts WHERE id`).
		WithArgs("nonexistent").
		WillReturnResult(pgxmock.NewResult("DELETE", 0))

	err := store.DeleteDraft(context.Background(), "nonexistent")

	assert.ErrorIs(t, err, ErrDraftNotFound)
}

func TestDraftStore_DeleteDraft_Mock_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectExec(`DELETE FROM drafts WHERE id`).
		WithArgs("draft-1").
		WillReturnError(errors.New("db error"))

	err := store.DeleteDraft(context.Background(), "draft-1")

	assert.Error(t, err)
}

func TestDraftStore_CreateDraftFromPush_Mock(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	commitSHAs := []string{"sha1"}
	commitSHAsJSON, _ := json.Marshal(commitSHAs)

	rows := pgxmock.NewRows(draftColumns).
		AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "before", "after", commitSHAsJSON, "", nil, "draft", now, now)

	mock.ExpectQuery(`INSERT INTO drafts`).
		WithArgs("user-1", "repo-1", "refs/heads/main", "before", "after", pgxmock.AnyArg(), 1, "").
		WillReturnRows(rows)

	draft, err := store.CreateDraftFromPush(context.Background(), "user-1", "repo-1", "refs/heads/main", "before", "after", commitSHAs)

	require.NoError(t, err)
	require.NotNil(t, draft)
	assert.Equal(t, "draft-1", draft.ID)
	assert.Equal(t, "", draft.GeneratedContent)
}

func TestDraftStore_GetDraftByPushSignature_Mock_Found(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	commitSHAsJSON, _ := json.Marshal([]string{"sha1"})

	rows := pgxmock.NewRows(draftColumns).
		AddRow("draft-1", "user-1", "repo-1", "refs/heads/main", "before", "after", commitSHAsJSON, "content", nil, "draft", now, now)

	mock.ExpectQuery(`SELECT id, user_id, repository_id`).
		WithArgs("repo-1", "before", "after").
		WillReturnRows(rows)

	draft, err := store.GetDraftByPushSignature(context.Background(), "repo-1", "before", "after")

	require.NoError(t, err)
	require.NotNil(t, draft)
	assert.Equal(t, "draft-1", draft.ID)
}

func TestDraftStore_GetDraftByPushSignature_Mock_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, user_id, repository_id`).
		WithArgs("repo-1", "before", "after").
		WillReturnError(pgx.ErrNoRows)

	draft, err := store.GetDraftByPushSignature(context.Background(), "repo-1", "before", "after")

	assert.NoError(t, err)
	assert.Nil(t, draft)
}

func TestDraftStore_GetDraftByPushSignature_Mock_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewDraftStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, user_id, repository_id`).
		WithArgs("repo-1", "before", "after").
		WillReturnError(errors.New("db error"))

	draft, err := store.GetDraftByPushSignature(context.Background(), "repo-1", "before", "after")

	assert.Error(t, err)
	assert.Nil(t, draft)
}
