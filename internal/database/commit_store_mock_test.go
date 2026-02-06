package database

import (
	"context"
	"errors"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommitStore_NewCommitStoreWithDB(t *testing.T) {
	mock := NewMockPool(t)
	store := NewCommitStoreWithDB(mock)
	require.NotNil(t, store)
}

func TestCommitStore_ListCommitsByUser_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewCommitStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"id", "commit_sha", "commit_message", "author"}).
		AddRow("commit-1", "abc123", "Fix bug", "alice").
		AddRow("commit-2", "def456", "Add feature", "bob")

	mock.ExpectQuery(`SELECT c.id, c.commit_sha, c.commit_message, c.author`).
		WithArgs("user-123").
		WillReturnRows(rows)

	commits, err := store.ListCommitsByUser(context.Background(), "user-123")

	require.NoError(t, err)
	require.Len(t, commits, 2)
	assert.Equal(t, "commit-1", commits[0].ID)
	assert.Equal(t, "abc123", commits[0].SHA)
	assert.Equal(t, "Fix bug", commits[0].Message)
	assert.Equal(t, "alice", commits[0].Author)
	assert.Equal(t, "commit-2", commits[1].ID)
}

func TestCommitStore_ListCommitsByUser_Empty(t *testing.T) {
	mock := NewMockPool(t)
	store := NewCommitStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"id", "commit_sha", "commit_message", "author"})

	mock.ExpectQuery(`SELECT c.id, c.commit_sha`).
		WithArgs("user-no-commits").
		WillReturnRows(rows)

	commits, err := store.ListCommitsByUser(context.Background(), "user-no-commits")

	require.NoError(t, err)
	assert.Empty(t, commits)
}

func TestCommitStore_ListCommitsByUser_QueryError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewCommitStoreWithDB(mock)

	mock.ExpectQuery(`SELECT c.id, c.commit_sha`).
		WithArgs("user-123").
		WillReturnError(errors.New("query failed"))

	commits, err := store.ListCommitsByUser(context.Background(), "user-123")

	assert.Error(t, err)
	assert.Nil(t, commits)
}

func TestCommitStore_ListCommitsByUser_ScanError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewCommitStoreWithDB(mock)

	// Return wrong number of columns to cause a scan error
	rows := pgxmock.NewRows([]string{"id", "commit_sha", "commit_message", "author"}).
		AddRow("commit-1", "abc123", "Fix bug", "alice").
		RowError(0, errors.New("scan error"))

	mock.ExpectQuery(`SELECT c.id, c.commit_sha`).
		WithArgs("user-123").
		WillReturnRows(rows)

	commits, err := store.ListCommitsByUser(context.Background(), "user-123")

	assert.Error(t, err)
	assert.Nil(t, commits)
}
