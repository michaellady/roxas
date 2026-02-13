package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mikelady/roxas/internal/services"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var credColumns = []string{"id", "user_id", "platform", "access_token", "refresh_token", "token_expires_at", "platform_user_id", "scopes", "created_at", "updated_at"}

func TestCredentialStore_NewCredentialStoreWithDB(t *testing.T) {
	store, err := NewCredentialStoreWithDB(nil, testEncryptionKey)
	require.NoError(t, err)
	require.NotNil(t, store)
}

func TestCredentialStore_NewCredentialStoreWithDB_InvalidKey(t *testing.T) {
	store, err := NewCredentialStoreWithDB(nil, []byte("short"))
	assert.Error(t, err)
	assert.Nil(t, store)
}

func TestCredentialStore_GetCredentials_Success(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	// Encrypt the token so it can be decrypted by the store
	encryptedToken, _ := store.encrypt("access-token-value")
	encryptedRefresh, _ := store.encrypt("refresh-token-value")
	now := time.Now().Truncate(time.Microsecond)
	platformUserID := "plat-user-1"
	scopes := "read,write"

	rows := pgxmock.NewRows(credColumns).
		AddRow("cred-1", "user-1", "linkedin", encryptedToken, &encryptedRefresh, &now, &platformUserID, &scopes, now, now)

	mock.ExpectQuery(`SELECT id, user_id, platform, access_token`).
		WithArgs("user-1", "linkedin").
		WillReturnRows(rows)

	creds, err := store.GetCredentials(context.Background(), "user-1", "linkedin")

	require.NoError(t, err)
	require.NotNil(t, creds)
	assert.Equal(t, "cred-1", creds.ID)
	assert.Equal(t, "user-1", creds.UserID)
	assert.Equal(t, "linkedin", creds.Platform)
	assert.Equal(t, "access-token-value", creds.AccessToken)
	assert.Equal(t, "refresh-token-value", creds.RefreshToken)
	assert.Equal(t, "plat-user-1", creds.PlatformUserID)
	assert.Equal(t, "read,write", creds.Scopes)
}

func TestCredentialStore_GetCredentials_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	mock.ExpectQuery(`SELECT id, user_id, platform`).
		WithArgs("user-1", "linkedin").
		WillReturnError(pgx.ErrNoRows)

	creds, err := store.GetCredentials(context.Background(), "user-1", "linkedin")

	assert.ErrorIs(t, err, services.ErrCredentialsNotFound)
	assert.Nil(t, creds)
}

func TestCredentialStore_GetCredentials_InvalidPlatform(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	creds, err := store.GetCredentials(context.Background(), "user-1", "invalid_platform")

	assert.ErrorIs(t, err, services.ErrInvalidPlatform)
	assert.Nil(t, creds)
}

func TestCredentialStore_GetCredentials_QueryError(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	mock.ExpectQuery(`SELECT id, user_id, platform`).
		WithArgs("user-1", "linkedin").
		WillReturnError(errors.New("connection refused"))

	creds, err := store.GetCredentials(context.Background(), "user-1", "linkedin")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "querying credentials")
	assert.Nil(t, creds)
}

func TestCredentialStore_GetCredentials_NilOptionalFields(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	encryptedToken, _ := store.encrypt("access-token")
	now := time.Now().Truncate(time.Microsecond)

	rows := pgxmock.NewRows(credColumns).
		AddRow("cred-1", "user-1", "linkedin", encryptedToken, nil, nil, nil, nil, now, now)

	mock.ExpectQuery(`SELECT id, user_id, platform`).
		WithArgs("user-1", "linkedin").
		WillReturnRows(rows)

	creds, err := store.GetCredentials(context.Background(), "user-1", "linkedin")

	require.NoError(t, err)
	require.NotNil(t, creds)
	assert.Equal(t, "access-token", creds.AccessToken)
	assert.Equal(t, "", creds.RefreshToken)
	assert.Nil(t, creds.TokenExpiresAt)
	assert.Equal(t, "", creds.PlatformUserID)
	assert.Equal(t, "", creds.Scopes)
}

func TestCredentialStore_SaveCredentials_Success(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	now := time.Now().Truncate(time.Microsecond)
	creds := &services.PlatformCredentials{
		UserID:         "user-1",
		Platform:       "linkedin",
		AccessToken:    "access-token",
		RefreshToken:   "refresh-token",
		TokenExpiresAt: &now,
		PlatformUserID: "plat-user",
		Scopes:         "read,write",
	}

	mock.ExpectExec(`INSERT INTO platform_credentials`).
		WithArgs("user-1", "linkedin", pgxmock.AnyArg(), pgxmock.AnyArg(), &now, pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := store.SaveCredentials(context.Background(), creds)

	assert.NoError(t, err)
}

func TestCredentialStore_SaveCredentials_InvalidPlatform(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	creds := &services.PlatformCredentials{
		UserID:      "user-1",
		Platform:    "invalid",
		AccessToken: "token",
	}

	err := store.SaveCredentials(context.Background(), creds)

	assert.ErrorIs(t, err, services.ErrInvalidPlatform)
}

func TestCredentialStore_SaveCredentials_NoRefreshToken(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	creds := &services.PlatformCredentials{
		UserID:      "user-1",
		Platform:    "linkedin",
		AccessToken: "access-token",
	}

	mock.ExpectExec(`INSERT INTO platform_credentials`).
		WithArgs("user-1", "linkedin", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := store.SaveCredentials(context.Background(), creds)

	assert.NoError(t, err)
}

func TestCredentialStore_SaveCredentials_ExecError(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	creds := &services.PlatformCredentials{
		UserID:      "user-1",
		Platform:    "linkedin",
		AccessToken: "token",
	}

	mock.ExpectExec(`INSERT INTO platform_credentials`).
		WithArgs("user-1", "linkedin", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnError(errors.New("db error"))

	err := store.SaveCredentials(context.Background(), creds)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "saving credentials")
}

func TestCredentialStore_DeleteCredentials_Success(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	mock.ExpectExec(`DELETE FROM platform_credentials`).
		WithArgs("user-1", "linkedin").
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	err := store.DeleteCredentials(context.Background(), "user-1", "linkedin")

	assert.NoError(t, err)
}

func TestCredentialStore_DeleteCredentials_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	mock.ExpectExec(`DELETE FROM platform_credentials`).
		WithArgs("user-1", "linkedin").
		WillReturnResult(pgxmock.NewResult("DELETE", 0))

	err := store.DeleteCredentials(context.Background(), "user-1", "linkedin")

	assert.ErrorIs(t, err, services.ErrCredentialsNotFound)
}

func TestCredentialStore_DeleteCredentials_InvalidPlatform(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	err := store.DeleteCredentials(context.Background(), "user-1", "invalid")

	assert.ErrorIs(t, err, services.ErrInvalidPlatform)
}

func TestCredentialStore_DeleteCredentials_ExecError(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	mock.ExpectExec(`DELETE FROM platform_credentials`).
		WithArgs("user-1", "linkedin").
		WillReturnError(errors.New("db error"))

	err := store.DeleteCredentials(context.Background(), "user-1", "linkedin")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "deleting credentials")
}

func TestCredentialStore_GetCredentialsForUser_Success(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	encryptedToken1, _ := store.encrypt("token-1")
	encryptedToken2, _ := store.encrypt("token-2")
	now := time.Now().Truncate(time.Microsecond)

	rows := pgxmock.NewRows(credColumns).
		AddRow("cred-1", "user-1", "linkedin", encryptedToken1, nil, nil, nil, nil, now, now).
		AddRow("cred-2", "user-1", "twitter", encryptedToken2, nil, nil, nil, nil, now, now)

	mock.ExpectQuery(`SELECT id, user_id, platform, access_token`).
		WithArgs("user-1").
		WillReturnRows(rows)

	creds, err := store.GetCredentialsForUser(context.Background(), "user-1")

	require.NoError(t, err)
	require.Len(t, creds, 2)
	assert.Equal(t, "token-1", creds[0].AccessToken)
	assert.Equal(t, "token-2", creds[1].AccessToken)
}

func TestCredentialStore_GetCredentialsForUser_Empty(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	rows := pgxmock.NewRows(credColumns)

	mock.ExpectQuery(`SELECT id, user_id, platform`).
		WithArgs("user-no-creds").
		WillReturnRows(rows)

	creds, err := store.GetCredentialsForUser(context.Background(), "user-no-creds")

	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestCredentialStore_GetCredentialsForUser_QueryError(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	mock.ExpectQuery(`SELECT id, user_id, platform`).
		WithArgs("user-1").
		WillReturnError(errors.New("query error"))

	creds, err := store.GetCredentialsForUser(context.Background(), "user-1")

	assert.Error(t, err)
	assert.Nil(t, creds)
}

func TestCredentialStore_GetCredentialsForUser_ScanError(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	encryptedToken, _ := store.encrypt("token")
	now := time.Now().Truncate(time.Microsecond)

	rows := pgxmock.NewRows(credColumns).
		AddRow("cred-1", "user-1", "linkedin", encryptedToken, nil, nil, nil, nil, now, now).
		RowError(0, errors.New("scan error"))

	mock.ExpectQuery(`SELECT id, user_id, platform`).
		WithArgs("user-1").
		WillReturnRows(rows)

	creds, err := store.GetCredentialsForUser(context.Background(), "user-1")

	assert.Error(t, err)
	assert.Nil(t, creds)
}

func TestCredentialStore_GetCredentialsForUser_WithAllFields(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	encryptedToken, _ := store.encrypt("token-val")
	encryptedRefresh, _ := store.encrypt("refresh-val")
	now := time.Now().Truncate(time.Microsecond)
	platformUserID := "plat-1"
	scopes := "read"

	rows := pgxmock.NewRows(credColumns).
		AddRow("cred-1", "user-1", "linkedin", encryptedToken, &encryptedRefresh, &now, &platformUserID, &scopes, now, now)

	mock.ExpectQuery(`SELECT id, user_id, platform`).
		WithArgs("user-1").
		WillReturnRows(rows)

	creds, err := store.GetCredentialsForUser(context.Background(), "user-1")

	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "token-val", creds[0].AccessToken)
	assert.Equal(t, "refresh-val", creds[0].RefreshToken)
	assert.Equal(t, "plat-1", creds[0].PlatformUserID)
	assert.Equal(t, "read", creds[0].Scopes)
}

func TestCredentialStore_GetExpiringCredentials_Success(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	encryptedToken, _ := store.encrypt("token")
	now := time.Now().Truncate(time.Microsecond)
	expiresAt := now.Add(30 * time.Minute)

	rows := pgxmock.NewRows(credColumns).
		AddRow("cred-1", "user-1", "linkedin", encryptedToken, nil, &expiresAt, nil, nil, now, now)

	mock.ExpectQuery(`SELECT id, user_id, platform, access_token`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(rows)

	creds, err := store.GetExpiringCredentials(context.Background(), 1*time.Hour)

	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "token", creds[0].AccessToken)
}

func TestCredentialStore_GetExpiringCredentials_Empty(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	rows := pgxmock.NewRows(credColumns)

	mock.ExpectQuery(`SELECT id, user_id, platform`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(rows)

	creds, err := store.GetExpiringCredentials(context.Background(), 1*time.Hour)

	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestCredentialStore_GetExpiringCredentials_QueryError(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	mock.ExpectQuery(`SELECT id, user_id, platform`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnError(errors.New("query error"))

	creds, err := store.GetExpiringCredentials(context.Background(), 1*time.Hour)

	assert.Error(t, err)
	assert.Nil(t, creds)
}

func TestCredentialStore_UpdateTokens_Success(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	now := time.Now().Truncate(time.Microsecond)

	mock.ExpectExec(`UPDATE platform_credentials`).
		WithArgs("user-1", "linkedin", pgxmock.AnyArg(), pgxmock.AnyArg(), &now).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := store.UpdateTokens(context.Background(), "user-1", "linkedin", "new-token", "new-refresh", &now)

	assert.NoError(t, err)
}

func TestCredentialStore_UpdateTokens_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	mock.ExpectExec(`UPDATE platform_credentials`).
		WithArgs("user-1", "linkedin", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := store.UpdateTokens(context.Background(), "user-1", "linkedin", "new-token", "", nil)

	assert.ErrorIs(t, err, services.ErrCredentialsNotFound)
}

func TestCredentialStore_UpdateTokens_InvalidPlatform(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	err := store.UpdateTokens(context.Background(), "user-1", "invalid", "token", "", nil)

	assert.ErrorIs(t, err, services.ErrInvalidPlatform)
}

func TestCredentialStore_UpdateTokens_ExecError(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	mock.ExpectExec(`UPDATE platform_credentials`).
		WithArgs("user-1", "linkedin", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnError(errors.New("db error"))

	err := store.UpdateTokens(context.Background(), "user-1", "linkedin", "token", "", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "updating tokens")
}

func TestCredentialStore_UpdateHealthStatus_Success(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	mock.ExpectExec(`UPDATE platform_credentials`).
		WithArgs("user-1", "linkedin", true, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := store.UpdateHealthStatus(context.Background(), "user-1", "linkedin", true, nil)

	assert.NoError(t, err)
}

func TestCredentialStore_UpdateHealthStatus_WithError(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	healthErr := "token expired"
	mock.ExpectExec(`UPDATE platform_credentials`).
		WithArgs("user-1", "linkedin", false, &healthErr).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := store.UpdateHealthStatus(context.Background(), "user-1", "linkedin", false, &healthErr)

	assert.NoError(t, err)
}

func TestCredentialStore_UpdateHealthStatus_NotFound(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	mock.ExpectExec(`UPDATE platform_credentials`).
		WithArgs("user-1", "linkedin", true, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := store.UpdateHealthStatus(context.Background(), "user-1", "linkedin", true, nil)

	assert.ErrorIs(t, err, services.ErrCredentialsNotFound)
}

func TestCredentialStore_UpdateHealthStatus_InvalidPlatform(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	err := store.UpdateHealthStatus(context.Background(), "user-1", "invalid", true, nil)

	assert.ErrorIs(t, err, services.ErrInvalidPlatform)
}

func TestCredentialStore_UpdateHealthStatus_ExecError(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	mock.ExpectExec(`UPDATE platform_credentials`).
		WithArgs("user-1", "linkedin", true, pgxmock.AnyArg()).
		WillReturnError(errors.New("db error"))

	err := store.UpdateHealthStatus(context.Background(), "user-1", "linkedin", true, nil)

	assert.Error(t, err)
}

func TestCredentialStore_GetCredentialsNeedingCheck_Success(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	encryptedToken, _ := store.encrypt("token")
	now := time.Now().Truncate(time.Microsecond)

	healthColumns := []string{"id", "user_id", "platform", "access_token", "refresh_token", "token_expires_at", "platform_user_id", "scopes", "created_at", "updated_at", "last_health_check", "is_healthy", "health_error", "last_successful_post"}

	isHealthy := true
	rows := pgxmock.NewRows(healthColumns).
		AddRow("cred-1", "user-1", "linkedin", encryptedToken, nil, nil, nil, nil, now, now, nil, &isHealthy, nil, nil)

	mock.ExpectQuery(`SELECT id, user_id, platform, access_token`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(rows)

	creds, err := store.GetCredentialsNeedingCheck(context.Background(), 1*time.Hour)

	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "token", creds[0].AccessToken)
	assert.True(t, creds[0].IsHealthy)
}

func TestCredentialStore_GetCredentialsNeedingCheck_NilHealthy(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	encryptedToken, _ := store.encrypt("token")
	now := time.Now().Truncate(time.Microsecond)

	healthColumns := []string{"id", "user_id", "platform", "access_token", "refresh_token", "token_expires_at", "platform_user_id", "scopes", "created_at", "updated_at", "last_health_check", "is_healthy", "health_error", "last_successful_post"}

	rows := pgxmock.NewRows(healthColumns).
		AddRow("cred-1", "user-1", "linkedin", encryptedToken, nil, nil, nil, nil, now, now, nil, nil, nil, nil)

	mock.ExpectQuery(`SELECT id, user_id, platform`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(rows)

	creds, err := store.GetCredentialsNeedingCheck(context.Background(), 1*time.Hour)

	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.True(t, creds[0].IsHealthy) // Default to true when NULL
}

func TestCredentialStore_GetCredentialsNeedingCheck_QueryError(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	mock.ExpectQuery(`SELECT id, user_id, platform`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnError(errors.New("query error"))

	creds, err := store.GetCredentialsNeedingCheck(context.Background(), 1*time.Hour)

	assert.Error(t, err)
	assert.Nil(t, creds)
}

func TestCredentialStore_GetCredentialsNeedingCheck_Empty(t *testing.T) {
	mock := NewMockPool(t)
	store, _ := NewCredentialStoreWithDB(mock, testEncryptionKey)

	healthColumns := []string{"id", "user_id", "platform", "access_token", "refresh_token", "token_expires_at", "platform_user_id", "scopes", "created_at", "updated_at", "last_health_check", "is_healthy", "health_error", "last_successful_post"}

	rows := pgxmock.NewRows(healthColumns)

	mock.ExpectQuery(`SELECT id, user_id, platform`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(rows)

	creds, err := store.GetCredentialsNeedingCheck(context.Background(), 1*time.Hour)

	require.NoError(t, err)
	assert.Empty(t, creds)
}
