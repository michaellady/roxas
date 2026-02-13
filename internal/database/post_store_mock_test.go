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

var postColumns = []string{"id", "commit_id", "draft_id", "platform", "platform_post_id", "platform_post_url", "content", "status", "error_message", "posted_at", "created_at"}

func TestPostStore_NewPostStoreWithDB(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)
	require.NotNil(t, store)
}

func TestPostStore_CreatePost_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	rows := pgxmock.NewRows(postColumns).
		AddRow("post-1", "commit-1", nil, "linkedin", nil, nil, "Test content", "draft", nil, nil, now)

	mock.ExpectQuery(`INSERT INTO posts`).
		WithArgs("commit-1", "linkedin", "Test content").
		WillReturnRows(rows)

	post, err := store.CreatePost(context.Background(), "commit-1", "linkedin", "Test content")

	require.NoError(t, err)
	require.NotNil(t, post)
	assert.Equal(t, "post-1", post.ID)
	assert.Equal(t, "commit-1", post.CommitID)
	assert.Equal(t, "linkedin", post.Platform)
	assert.Equal(t, "Test content", post.Content)
	assert.Equal(t, "draft", post.Status)
	assert.Equal(t, now, post.CreatedAt)
}

func TestPostStore_CreatePost_DuplicatePost(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	pgErr := &pgconn.PgError{Code: "23505"}
	mock.ExpectQuery(`INSERT INTO posts`).
		WithArgs("commit-1", "linkedin", "content").
		WillReturnError(pgErr)

	post, err := store.CreatePost(context.Background(), "commit-1", "linkedin", "content")

	assert.ErrorIs(t, err, handlers.ErrDuplicatePost)
	assert.Nil(t, post)
}

func TestPostStore_CreatePost_DatabaseError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	mock.ExpectQuery(`INSERT INTO posts`).
		WithArgs("commit-1", "linkedin", "content").
		WillReturnError(errors.New("db error"))

	post, err := store.CreatePost(context.Background(), "commit-1", "linkedin", "content")

	assert.Error(t, err)
	assert.Nil(t, post)
}

func TestPostStore_CreatePostFromDraft_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	draftID := "draft-1"
	rows := pgxmock.NewRows(postColumns).
		AddRow("post-1", "", &draftID, "twitter", nil, nil, "Draft content", "draft", nil, nil, now)

	mock.ExpectQuery(`INSERT INTO posts`).
		WithArgs("draft-1", "twitter", "Draft content").
		WillReturnRows(rows)

	post, err := store.CreatePostFromDraft(context.Background(), "draft-1", "twitter", "Draft content")

	require.NoError(t, err)
	require.NotNil(t, post)
	assert.Equal(t, "post-1", post.ID)
	assert.Equal(t, &draftID, post.DraftID)
	assert.Equal(t, "twitter", post.Platform)
}

func TestPostStore_CreatePostFromDraft_Duplicate(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	pgErr := &pgconn.PgError{Code: "23505"}
	mock.ExpectQuery(`INSERT INTO posts`).
		WithArgs("draft-1", "twitter", "content").
		WillReturnError(pgErr)

	post, err := store.CreatePostFromDraft(context.Background(), "draft-1", "twitter", "content")

	assert.ErrorIs(t, err, handlers.ErrDuplicatePost)
	assert.Nil(t, post)
}

func TestPostStore_CreatePostFromDraft_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	mock.ExpectQuery(`INSERT INTO posts`).
		WithArgs("draft-1", "twitter", "content").
		WillReturnError(errors.New("db error"))

	post, err := store.CreatePostFromDraft(context.Background(), "draft-1", "twitter", "content")

	assert.Error(t, err)
	assert.Nil(t, post)
}

func TestPostStore_GetPostByID_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	rows := pgxmock.NewRows(postColumns).
		AddRow("post-1", "commit-1", nil, "linkedin", nil, nil, "Content", "posted", nil, nil, now)

	mock.ExpectQuery(`SELECT id, commit_id, draft_id, platform`).
		WithArgs("post-1").
		WillReturnRows(rows)

	post, err := store.GetPostByID(context.Background(), "post-1")

	require.NoError(t, err)
	require.NotNil(t, post)
	assert.Equal(t, "post-1", post.ID)
	assert.Equal(t, "posted", post.Status)
}

func TestPostStore_GetPostByID_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, commit_id`).
		WithArgs("nonexistent").
		WillReturnError(pgx.ErrNoRows)

	post, err := store.GetPostByID(context.Background(), "nonexistent")

	assert.NoError(t, err)
	assert.Nil(t, post)
}

func TestPostStore_GetPostByID_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, commit_id`).
		WithArgs("post-1").
		WillReturnError(errors.New("db error"))

	post, err := store.GetPostByID(context.Background(), "post-1")

	assert.Error(t, err)
	assert.Nil(t, post)
}

func TestPostStore_GetPostsByUserID_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	rows := pgxmock.NewRows([]string{"id", "commit_id", "draft_id", "platform", "platform_post_id", "platform_post_url", "content", "status", "error_message", "posted_at", "created_at"}).
		AddRow("post-1", "commit-1", nil, "linkedin", nil, nil, "Content 1", "posted", nil, nil, now).
		AddRow("post-2", "commit-2", nil, "twitter", nil, nil, "Content 2", "draft", nil, nil, now)

	mock.ExpectQuery(`SELECT p.id, p.commit_id, p.draft_id`).
		WithArgs("user-123").
		WillReturnRows(rows)

	posts, err := store.GetPostsByUserID(context.Background(), "user-123")

	require.NoError(t, err)
	require.Len(t, posts, 2)
	assert.Equal(t, "post-1", posts[0].ID)
	assert.Equal(t, "post-2", posts[1].ID)
}

func TestPostStore_GetPostsByUserID_Empty(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"id", "commit_id", "draft_id", "platform", "platform_post_id", "platform_post_url", "content", "status", "error_message", "posted_at", "created_at"})

	mock.ExpectQuery(`SELECT p.id, p.commit_id`).
		WithArgs("user-no-posts").
		WillReturnRows(rows)

	posts, err := store.GetPostsByUserID(context.Background(), "user-no-posts")

	require.NoError(t, err)
	assert.Empty(t, posts)
}

func TestPostStore_GetPostsByUserID_QueryError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	mock.ExpectQuery(`SELECT p.id, p.commit_id`).
		WithArgs("user-123").
		WillReturnError(errors.New("query error"))

	posts, err := store.GetPostsByUserID(context.Background(), "user-123")

	assert.Error(t, err)
	assert.Nil(t, posts)
}

func TestPostStore_GetPostsByUserID_ScanError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"id", "commit_id", "draft_id", "platform", "platform_post_id", "platform_post_url", "content", "status", "error_message", "posted_at", "created_at"}).
		AddRow("post-1", "commit-1", nil, "linkedin", nil, nil, "Content", "posted", nil, nil, time.Now()).
		RowError(0, errors.New("scan error"))

	mock.ExpectQuery(`SELECT p.id, p.commit_id`).
		WithArgs("user-123").
		WillReturnRows(rows)

	posts, err := store.GetPostsByUserID(context.Background(), "user-123")

	assert.Error(t, err)
	assert.Nil(t, posts)
}

func TestPostStore_ListPostsByUser_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"id", "platform", "content", "status"}).
		AddRow("post-1", "linkedin", "Content 1", "posted").
		AddRow("post-2", "twitter", "Content 2", "draft")

	mock.ExpectQuery(`SELECT p.id, p.platform, p.content, p.status`).
		WithArgs("user-123").
		WillReturnRows(rows)

	posts, err := store.ListPostsByUser(context.Background(), "user-123")

	require.NoError(t, err)
	require.Len(t, posts, 2)
	assert.Equal(t, "post-1", posts[0].ID)
	assert.Equal(t, "linkedin", posts[0].Platform)
}

func TestPostStore_ListPostsByUser_Empty(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"id", "platform", "content", "status"})

	mock.ExpectQuery(`SELECT p.id, p.platform`).
		WithArgs("user-123").
		WillReturnRows(rows)

	posts, err := store.ListPostsByUser(context.Background(), "user-123")

	require.NoError(t, err)
	assert.Empty(t, posts)
}

func TestPostStore_ListPostsByUser_QueryError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	mock.ExpectQuery(`SELECT p.id, p.platform`).
		WithArgs("user-123").
		WillReturnError(errors.New("query error"))

	posts, err := store.ListPostsByUser(context.Background(), "user-123")

	assert.Error(t, err)
	assert.Nil(t, posts)
}

func TestPostStore_ListPostsByUser_ScanError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"id", "platform", "content", "status"}).
		AddRow("post-1", "linkedin", "Content", "posted").
		RowError(0, errors.New("scan error"))

	mock.ExpectQuery(`SELECT p.id, p.platform`).
		WithArgs("user-123").
		WillReturnRows(rows)

	posts, err := store.ListPostsByUser(context.Background(), "user-123")

	assert.Error(t, err)
	assert.Nil(t, posts)
}

func TestPostStore_UpdatePostStatus_Mock_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	mock.ExpectExec(`UPDATE posts SET status`).
		WithArgs("posted", "post-1").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := store.UpdatePostStatus(context.Background(), "post-1", "posted")

	assert.NoError(t, err)
}

func TestPostStore_UpdatePostStatus_Mock_InvalidStatus(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	err := store.UpdatePostStatus(context.Background(), "post-1", "invalid")

	assert.ErrorIs(t, err, ErrInvalidStatus)
}

func TestPostStore_UpdatePostStatus_Mock_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	mock.ExpectExec(`UPDATE posts SET status`).
		WithArgs("posted", "nonexistent").
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	// Verify post doesn't exist
	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("nonexistent").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))

	err := store.UpdatePostStatus(context.Background(), "nonexistent", "posted")

	assert.ErrorIs(t, err, ErrPostNotFound)
}

func TestPostStore_UpdatePostStatus_Mock_SameStatus(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	// When status doesn't change, RowsAffected can be 0 but post exists
	mock.ExpectExec(`UPDATE posts SET status`).
		WithArgs("draft", "post-1").
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("post-1").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))

	err := store.UpdatePostStatus(context.Background(), "post-1", "draft")

	assert.NoError(t, err)
}

func TestPostStore_UpdatePostStatus_Mock_ExecError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	mock.ExpectExec(`UPDATE posts SET status`).
		WithArgs("posted", "post-1").
		WillReturnError(errors.New("db error"))

	err := store.UpdatePostStatus(context.Background(), "post-1", "posted")

	assert.Error(t, err)
}

func TestPostStore_UpdatePostStatus_Mock_CheckConstraintViolation(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	pgErr := &pgconn.PgError{Code: "23514"}
	mock.ExpectExec(`UPDATE posts SET status`).
		WithArgs("posted", "post-1").
		WillReturnError(pgErr)

	err := store.UpdatePostStatus(context.Background(), "post-1", "posted")

	assert.ErrorIs(t, err, ErrInvalidStatus)
}

func TestPostStore_UpdatePostStatus_Mock_ExistsCheckError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	mock.ExpectExec(`UPDATE posts SET status`).
		WithArgs("posted", "post-1").
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("post-1").
		WillReturnError(errors.New("check error"))

	err := store.UpdatePostStatus(context.Background(), "post-1", "posted")

	assert.Error(t, err)
}

func TestPostStore_CountDraftsByUser_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"count"}).AddRow(5)

	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("user-123").
		WillReturnRows(rows)

	count, err := store.CountDraftsByUser(context.Background(), "user-123")

	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestPostStore_CountDraftsByUser_Zero(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"count"}).AddRow(0)

	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("user-123").
		WillReturnRows(rows)

	count, err := store.CountDraftsByUser(context.Background(), "user-123")

	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestPostStore_CountDraftsByUser_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewPostStoreWithDB(mock)

	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("user-123").
		WillReturnError(errors.New("db error"))

	count, err := store.CountDraftsByUser(context.Background(), "user-123")

	assert.Error(t, err)
	assert.Equal(t, 0, count)
}
