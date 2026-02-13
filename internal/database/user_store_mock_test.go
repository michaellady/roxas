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

func TestUserStore_CreateUser_Mock_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewUserStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	rows := pgxmock.NewRows([]string{"id", "email", "password_hash", "github_id", "github_login", "created_at", "updated_at"}).
		AddRow("user-123", "test@example.com", stringPtr("hashed"), nil, nil, now, now)

	mock.ExpectQuery(`INSERT INTO users`).
		WithArgs("test@example.com", "hashed").
		WillReturnRows(rows)

	user, err := store.CreateUser(context.Background(), "test@example.com", "hashed")

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "user-123", user.ID)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "hashed", user.PasswordHash)
	assert.Equal(t, now, user.CreatedAt)
	assert.Equal(t, now, user.UpdatedAt)
}

func stringPtr(s string) *string { return &s }

func TestUserStore_CreateUser_Mock_DuplicateEmail(t *testing.T) {
	mock := NewMockPool(t)
	store := NewUserStoreWithDB(mock)

	pgErr := &pgconn.PgError{Code: "23505"}
	mock.ExpectQuery(`INSERT INTO users`).
		WithArgs("dup@example.com", "hashed").
		WillReturnError(pgErr)

	user, err := store.CreateUser(context.Background(), "dup@example.com", "hashed")

	assert.ErrorIs(t, err, handlers.ErrDuplicateEmail)
	assert.Nil(t, user)
}

func TestUserStore_CreateUser_Mock_DatabaseError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewUserStoreWithDB(mock)

	dbErr := errors.New("connection refused")
	mock.ExpectQuery(`INSERT INTO users`).
		WithArgs("test@example.com", "hashed").
		WillReturnError(dbErr)

	user, err := store.CreateUser(context.Background(), "test@example.com", "hashed")

	assert.Error(t, err)
	assert.Nil(t, user)
}

func TestUserStore_GetUserByEmail_Mock_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewUserStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	rows := pgxmock.NewRows([]string{"id", "email", "password_hash", "github_id", "github_login", "created_at", "updated_at"}).
		AddRow("user-123", "test@example.com", stringPtr("hashed"), nil, nil, now, now)

	mock.ExpectQuery(`SELECT id, email, password_hash`).
		WithArgs("test@example.com").
		WillReturnRows(rows)

	user, err := store.GetUserByEmail(context.Background(), "test@example.com")

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "user-123", user.ID)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, now, user.CreatedAt)
	assert.Equal(t, now, user.UpdatedAt)
}

func TestUserStore_GetUserByEmail_Mock_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewUserStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, email, password_hash`).
		WithArgs("unknown@example.com").
		WillReturnError(pgx.ErrNoRows)

	user, err := store.GetUserByEmail(context.Background(), "unknown@example.com")

	assert.NoError(t, err)
	assert.Nil(t, user)
}

func TestUserStore_GetUserByEmail_Mock_DatabaseError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewUserStoreWithDB(mock)

	dbErr := errors.New("connection failed")
	mock.ExpectQuery(`SELECT id, email, password_hash`).
		WithArgs("test@example.com").
		WillReturnError(dbErr)

	user, err := store.GetUserByEmail(context.Background(), "test@example.com")

	assert.Error(t, err)
	assert.Nil(t, user)
}

var testUserColumns = []string{"id", "email", "password_hash", "github_id", "github_login", "created_at", "updated_at"}

func int64Ptr(i int64) *int64 { return &i }

func TestUserStore_GetOrCreateByGitHub_ExistingByGitHubID(t *testing.T) {
	mock := NewMockPool(t)
	store := NewUserStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	ghID := int64(12345)
	ghLogin := "testuser"

	// First query: find by github_id -> found
	mock.ExpectQuery(`SELECT .+ FROM users WHERE github_id`).
		WithArgs(int64(12345)).
		WillReturnRows(pgxmock.NewRows(testUserColumns).
			AddRow("user-1", "test@users.noreply.github.com", nil, &ghID, &ghLogin, now, now))

	user, created, err := store.GetOrCreateByGitHub(context.Background(), 12345, "testuser", "test@users.noreply.github.com")

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "user-1", user.ID)
	assert.False(t, created)
}

func TestUserStore_GetOrCreateByGitHub_LinkByEmail(t *testing.T) {
	mock := NewMockPool(t)
	store := NewUserStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	ghID := int64(12345)
	ghLogin := "testuser"

	// First query: find by github_id -> not found
	mock.ExpectQuery(`SELECT .+ FROM users WHERE github_id`).
		WithArgs(int64(12345)).
		WillReturnError(pgx.ErrNoRows)

	// Second query: update by email -> found and linked
	mock.ExpectQuery(`UPDATE users SET github_id`).
		WithArgs(int64(12345), "testuser", "test@example.com").
		WillReturnRows(pgxmock.NewRows(testUserColumns).
			AddRow("user-1", "test@example.com", stringPtr("hashed"), &ghID, &ghLogin, now, now))

	user, created, err := store.GetOrCreateByGitHub(context.Background(), 12345, "testuser", "test@example.com")

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "user-1", user.ID)
	assert.False(t, created)
}

func TestUserStore_GetOrCreateByGitHub_CreateNew(t *testing.T) {
	mock := NewMockPool(t)
	store := NewUserStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	ghID := int64(12345)
	ghLogin := "testuser"

	// First query: find by github_id -> not found
	mock.ExpectQuery(`SELECT .+ FROM users WHERE github_id`).
		WithArgs(int64(12345)).
		WillReturnError(pgx.ErrNoRows)

	// Second query: update by email -> not found
	mock.ExpectQuery(`UPDATE users SET github_id`).
		WithArgs(int64(12345), "testuser", "new@users.noreply.github.com").
		WillReturnError(pgx.ErrNoRows)

	// Third query: insert new user
	mock.ExpectQuery(`INSERT INTO users`).
		WithArgs("new@users.noreply.github.com", int64(12345), "testuser").
		WillReturnRows(pgxmock.NewRows(testUserColumns).
			AddRow("user-new", "new@users.noreply.github.com", nil, &ghID, &ghLogin, now, now))

	user, created, err := store.GetOrCreateByGitHub(context.Background(), 12345, "testuser", "new@users.noreply.github.com")

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "user-new", user.ID)
	assert.True(t, created)
}

func TestUserStore_GetOrCreateByGitHub_DBError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewUserStoreWithDB(mock)

	// First query: find by github_id -> db error
	mock.ExpectQuery(`SELECT .+ FROM users WHERE github_id`).
		WithArgs(int64(12345)).
		WillReturnError(errors.New("db connection error"))

	user, created, err := store.GetOrCreateByGitHub(context.Background(), 12345, "testuser", "test@example.com")

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.False(t, created)
}

func TestUserStore_LinkGitHubIdentity_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewUserStoreWithDB(mock)

	mock.ExpectExec(`UPDATE users SET github_id`).
		WithArgs(int64(12345), "testuser", "user-1").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := store.LinkGitHubIdentity(context.Background(), "user-1", 12345, "testuser")

	assert.NoError(t, err)
}

func TestUserStore_LinkGitHubIdentity_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewUserStoreWithDB(mock)

	mock.ExpectExec(`UPDATE users SET github_id`).
		WithArgs(int64(12345), "testuser", "nonexistent").
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := store.LinkGitHubIdentity(context.Background(), "nonexistent", 12345, "testuser")

	assert.ErrorIs(t, err, pgx.ErrNoRows)
}

func TestUserStore_LinkGitHubIdentity_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewUserStoreWithDB(mock)

	mock.ExpectExec(`UPDATE users SET github_id`).
		WithArgs(int64(12345), "testuser", "user-1").
		WillReturnError(errors.New("db error"))

	err := store.LinkGitHubIdentity(context.Background(), "user-1", 12345, "testuser")

	assert.Error(t, err)
}
