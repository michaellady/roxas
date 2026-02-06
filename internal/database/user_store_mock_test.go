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
	rows := pgxmock.NewRows([]string{"id", "email", "password_hash", "created_at", "updated_at"}).
		AddRow("user-123", "test@example.com", "hashed", now, now)

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
	rows := pgxmock.NewRows([]string{"id", "email", "password_hash", "created_at", "updated_at"}).
		AddRow("user-123", "test@example.com", "hashed", now, now)

	mock.ExpectQuery(`SELECT id, email, password_hash, created_at, updated_at`).
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
