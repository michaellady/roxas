package database

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Installation represents a GitHub App installation record
type Installation struct {
	ID             string
	InstallationID int64
	UserID         string
	AccountLogin   string
	AccountID      int64
	AccountType    string
	SuspendedAt    *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// InstallationStore implements CRUD for github_app_installations
type InstallationStore struct {
	db DBTX
}

// NewInstallationStore creates a new database-backed installation store
func NewInstallationStore(pool *Pool) *InstallationStore {
	return &InstallationStore{db: pool}
}

// NewInstallationStoreWithDB creates an installation store with a custom DBTX implementation.
// This is primarily used for testing with pgxmock.
func NewInstallationStoreWithDB(db DBTX) *InstallationStore {
	return &InstallationStore{db: db}
}

// UpsertInstallation inserts or updates a GitHub App installation
func (s *InstallationStore) UpsertInstallation(ctx context.Context, inst *Installation) (*Installation, error) {
	var result Installation
	err := s.db.QueryRow(ctx,
		`INSERT INTO github_app_installations (installation_id, user_id, account_login, account_id, account_type)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (installation_id) DO UPDATE SET
		   user_id = EXCLUDED.user_id,
		   account_login = EXCLUDED.account_login,
		   account_id = EXCLUDED.account_id,
		   account_type = EXCLUDED.account_type,
		   suspended_at = NULL
		 RETURNING id, installation_id, user_id, account_login, account_id, account_type, suspended_at, created_at, updated_at`,
		inst.InstallationID, inst.UserID, inst.AccountLogin, inst.AccountID, inst.AccountType,
	).Scan(&result.ID, &result.InstallationID, &result.UserID, &result.AccountLogin,
		&result.AccountID, &result.AccountType, &result.SuspendedAt, &result.CreatedAt, &result.UpdatedAt)

	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetInstallationByID retrieves an installation by its GitHub installation ID
func (s *InstallationStore) GetInstallationByID(ctx context.Context, installationID int64) (*Installation, error) {
	var inst Installation
	err := s.db.QueryRow(ctx,
		`SELECT id, installation_id, user_id, account_login, account_id, account_type, suspended_at, created_at, updated_at
		 FROM github_app_installations
		 WHERE installation_id = $1`,
		installationID,
	).Scan(&inst.ID, &inst.InstallationID, &inst.UserID, &inst.AccountLogin,
		&inst.AccountID, &inst.AccountType, &inst.SuspendedAt, &inst.CreatedAt, &inst.UpdatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &inst, nil
}

// GetInstallationByUserID retrieves an installation by user ID
func (s *InstallationStore) GetInstallationByUserID(ctx context.Context, userID string) (*Installation, error) {
	var inst Installation
	err := s.db.QueryRow(ctx,
		`SELECT id, installation_id, user_id, account_login, account_id, account_type, suspended_at, created_at, updated_at
		 FROM github_app_installations
		 WHERE user_id = $1`,
		userID,
	).Scan(&inst.ID, &inst.InstallationID, &inst.UserID, &inst.AccountLogin,
		&inst.AccountID, &inst.AccountType, &inst.SuspendedAt, &inst.CreatedAt, &inst.UpdatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &inst, nil
}

// DeleteInstallation removes an installation by its GitHub installation ID
func (s *InstallationStore) DeleteInstallation(ctx context.Context, installationID int64) error {
	result, err := s.db.Exec(ctx,
		`DELETE FROM github_app_installations WHERE installation_id = $1`,
		installationID,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// SuspendInstallation marks an installation as suspended
func (s *InstallationStore) SuspendInstallation(ctx context.Context, installationID int64) error {
	result, err := s.db.Exec(ctx,
		`UPDATE github_app_installations SET suspended_at = NOW() WHERE installation_id = $1`,
		installationID,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// UnsuspendInstallation clears the suspended status
func (s *InstallationStore) UnsuspendInstallation(ctx context.Context, installationID int64) error {
	result, err := s.db.Exec(ctx,
		`UPDATE github_app_installations SET suspended_at = NULL WHERE installation_id = $1`,
		installationID,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
