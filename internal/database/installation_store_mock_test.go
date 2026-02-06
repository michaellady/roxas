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

var installColumns = []string{"id", "installation_id", "user_id", "account_login", "account_id", "account_type", "suspended_at", "created_at", "updated_at"}

func TestInstallationStore_NewInstallationStoreWithDB(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)
	require.NotNil(t, store)
}

func TestInstallationStore_UpsertInstallation_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)

	rows := pgxmock.NewRows(installColumns).
		AddRow("inst-1", int64(12345), "user-1", "test-org", int64(999), "Organization", nil, now, now)

	mock.ExpectQuery(`INSERT INTO github_app_installations`).
		WithArgs(int64(12345), "user-1", "test-org", int64(999), "Organization").
		WillReturnRows(rows)

	inst, err := store.UpsertInstallation(context.Background(), &Installation{
		InstallationID: 12345,
		UserID:         "user-1",
		AccountLogin:   "test-org",
		AccountID:      999,
		AccountType:    "Organization",
	})

	require.NoError(t, err)
	require.NotNil(t, inst)
	assert.Equal(t, "inst-1", inst.ID)
	assert.Equal(t, int64(12345), inst.InstallationID)
	assert.Equal(t, "user-1", inst.UserID)
	assert.Equal(t, "test-org", inst.AccountLogin)
	assert.Equal(t, int64(999), inst.AccountID)
	assert.Equal(t, "Organization", inst.AccountType)
	assert.Nil(t, inst.SuspendedAt)
	assert.Equal(t, now, inst.CreatedAt)
	assert.Equal(t, now, inst.UpdatedAt)
}

func TestInstallationStore_UpsertInstallation_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)

	mock.ExpectQuery(`INSERT INTO github_app_installations`).
		WithArgs(int64(12345), "user-1", "test-org", int64(999), "Organization").
		WillReturnError(errors.New("db error"))

	inst, err := store.UpsertInstallation(context.Background(), &Installation{
		InstallationID: 12345,
		UserID:         "user-1",
		AccountLogin:   "test-org",
		AccountID:      999,
		AccountType:    "Organization",
	})

	assert.Error(t, err)
	assert.Nil(t, inst)
}

func TestInstallationStore_GetInstallationByID_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)

	rows := pgxmock.NewRows(installColumns).
		AddRow("inst-1", int64(12345), "user-1", "test-org", int64(999), "Organization", nil, now, now)

	mock.ExpectQuery(`SELECT id, installation_id, user_id`).
		WithArgs(int64(12345)).
		WillReturnRows(rows)

	inst, err := store.GetInstallationByID(context.Background(), 12345)

	require.NoError(t, err)
	require.NotNil(t, inst)
	assert.Equal(t, "inst-1", inst.ID)
	assert.Equal(t, int64(12345), inst.InstallationID)
	assert.Equal(t, "user-1", inst.UserID)
	assert.Equal(t, "test-org", inst.AccountLogin)
	assert.Equal(t, int64(999), inst.AccountID)
	assert.Equal(t, "Organization", inst.AccountType)
	assert.Nil(t, inst.SuspendedAt)
	assert.Equal(t, now, inst.CreatedAt)
	assert.Equal(t, now, inst.UpdatedAt)
}

func TestInstallationStore_GetInstallationByID_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, installation_id, user_id`).
		WithArgs(int64(99999)).
		WillReturnError(pgx.ErrNoRows)

	inst, err := store.GetInstallationByID(context.Background(), 99999)

	assert.NoError(t, err)
	assert.Nil(t, inst)
}

func TestInstallationStore_GetInstallationByID_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, installation_id, user_id`).
		WithArgs(int64(12345)).
		WillReturnError(errors.New("db error"))

	inst, err := store.GetInstallationByID(context.Background(), 12345)

	assert.Error(t, err)
	assert.Nil(t, inst)
}

func TestInstallationStore_GetInstallationByUserID_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)

	rows := pgxmock.NewRows(installColumns).
		AddRow("inst-1", int64(12345), "user-1", "test-user", int64(888), "User", nil, now, now)

	mock.ExpectQuery(`SELECT id, installation_id, user_id`).
		WithArgs("user-1").
		WillReturnRows(rows)

	inst, err := store.GetInstallationByUserID(context.Background(), "user-1")

	require.NoError(t, err)
	require.NotNil(t, inst)
	assert.Equal(t, "inst-1", inst.ID)
	assert.Equal(t, int64(12345), inst.InstallationID)
	assert.Equal(t, "user-1", inst.UserID)
	assert.Equal(t, "test-user", inst.AccountLogin)
	assert.Equal(t, int64(888), inst.AccountID)
	assert.Equal(t, "User", inst.AccountType)
}

func TestInstallationStore_GetInstallationByUserID_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, installation_id, user_id`).
		WithArgs("nonexistent").
		WillReturnError(pgx.ErrNoRows)

	inst, err := store.GetInstallationByUserID(context.Background(), "nonexistent")

	assert.NoError(t, err)
	assert.Nil(t, inst)
}

func TestInstallationStore_DeleteInstallation_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)

	mock.ExpectExec(`DELETE FROM github_app_installations WHERE installation_id`).
		WithArgs(int64(12345)).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	err := store.DeleteInstallation(context.Background(), 12345)

	assert.NoError(t, err)
}

func TestInstallationStore_DeleteInstallation_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)

	mock.ExpectExec(`DELETE FROM github_app_installations WHERE installation_id`).
		WithArgs(int64(99999)).
		WillReturnResult(pgxmock.NewResult("DELETE", 0))

	err := store.DeleteInstallation(context.Background(), 99999)

	assert.ErrorIs(t, err, pgx.ErrNoRows)
}

func TestInstallationStore_SuspendInstallation_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)

	mock.ExpectExec(`UPDATE github_app_installations SET suspended_at`).
		WithArgs(int64(12345)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := store.SuspendInstallation(context.Background(), 12345)

	assert.NoError(t, err)
}

func TestInstallationStore_SuspendInstallation_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)

	mock.ExpectExec(`UPDATE github_app_installations SET suspended_at`).
		WithArgs(int64(99999)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := store.SuspendInstallation(context.Background(), 99999)

	assert.ErrorIs(t, err, pgx.ErrNoRows)
}

func TestInstallationStore_UnsuspendInstallation_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)

	mock.ExpectExec(`UPDATE github_app_installations SET suspended_at`).
		WithArgs(int64(12345)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := store.UnsuspendInstallation(context.Background(), 12345)

	assert.NoError(t, err)
}

func TestInstallationStore_UnsuspendInstallation_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store := NewInstallationStoreWithDB(mock)

	mock.ExpectExec(`UPDATE github_app_installations SET suspended_at`).
		WithArgs(int64(99999)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := store.UnsuspendInstallation(context.Background(), 99999)

	assert.ErrorIs(t, err, pgx.ErrNoRows)
}
