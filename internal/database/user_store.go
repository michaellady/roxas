package database

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mikelady/roxas/internal/handlers"
	"github.com/mikelady/roxas/internal/web"
)

// Compile-time interface compliance checks
var (
	_ handlers.UserStore = (*UserStore)(nil)
	_ web.UserStore      = (*UserStore)(nil)
)

// UserStore implements handlers.UserStore using PostgreSQL
type UserStore struct {
	db DBTX
}

// NewUserStore creates a new database-backed user store
func NewUserStore(pool *Pool) *UserStore {
	return &UserStore{db: pool}
}

// NewUserStoreWithDB creates a user store with a custom DBTX implementation.
// This is primarily used for testing with pgxmock.
func NewUserStoreWithDB(db DBTX) *UserStore {
	return &UserStore{db: db}
}

// scanUser scans a user row into a handlers.User, handling nullable fields.
func scanUser(row pgx.Row) (*handlers.User, error) {
	var user handlers.User
	var passwordHash *string
	var createdAt, updatedAt time.Time

	err := row.Scan(&user.ID, &user.Email, &passwordHash, &user.GitHubID, &user.GitHubLogin, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}

	if passwordHash != nil {
		user.PasswordHash = *passwordHash
	}
	user.CreatedAt = createdAt
	user.UpdatedAt = updatedAt
	return &user, nil
}

const userColumns = `id, email, password_hash, github_id, github_login, created_at, updated_at`

// CreateUser creates a new user in the database
func (s *UserStore) CreateUser(ctx context.Context, email, passwordHash string) (*handlers.User, error) {
	row := s.db.QueryRow(ctx,
		`INSERT INTO users (email, password_hash)
		 VALUES ($1, $2)
		 RETURNING `+userColumns,
		email, passwordHash,
	)
	user, err := scanUser(row)
	if err != nil {
		// Check for unique constraint violation (duplicate email)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, handlers.ErrDuplicateEmail
		}
		return nil, err
	}

	return user, nil
}

// GetUserByEmail retrieves a user by email address
func (s *UserStore) GetUserByEmail(ctx context.Context, email string) (*handlers.User, error) {
	row := s.db.QueryRow(ctx,
		`SELECT `+userColumns+`
		 FROM users
		 WHERE email = $1`,
		email,
	)
	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // User not found - return nil, nil per interface contract
		}
		return nil, err
	}

	return user, nil
}

// GetUserByID retrieves a user by their ID.
func (s *UserStore) GetUserByID(ctx context.Context, userID string) (*handlers.User, error) {
	row := s.db.QueryRow(ctx,
		`SELECT `+userColumns+`
		 FROM users
		 WHERE id = $1`,
		userID,
	)
	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return user, nil
}

// GetOrCreateByGitHub finds a user by github_id, or creates a new one without a password.
// Returns the user and whether it was newly created.
func (s *UserStore) GetOrCreateByGitHub(ctx context.Context, githubID int64, githubLogin, email string) (*handlers.User, bool, error) {
	// Try to find existing user by github_id
	row := s.db.QueryRow(ctx,
		`SELECT `+userColumns+`
		 FROM users
		 WHERE github_id = $1`,
		githubID,
	)
	user, err := scanUser(row)
	if err == nil {
		return user, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}

	// Try to find by email and link GitHub identity
	if email != "" {
		row = s.db.QueryRow(ctx,
			`UPDATE users SET github_id = $1, github_login = $2
			 WHERE email = $3
			 RETURNING `+userColumns,
			githubID, githubLogin, email,
		)
		user, err = scanUser(row)
		if err == nil {
			return user, false, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, false, err
		}
	}

	// Create new user (no password)
	row = s.db.QueryRow(ctx,
		`INSERT INTO users (email, github_id, github_login)
		 VALUES ($1, $2, $3)
		 RETURNING `+userColumns,
		email, githubID, githubLogin,
	)
	user, err = scanUser(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, false, handlers.ErrDuplicateEmail
		}
		return nil, false, err
	}

	return user, true, nil
}

// LinkGitHubIdentity links a GitHub identity to an existing user.
// Used when an existing email/password user installs the GitHub App.
func (s *UserStore) LinkGitHubIdentity(ctx context.Context, userID string, githubID int64, githubLogin string) error {
	result, err := s.db.Exec(ctx,
		`UPDATE users SET github_id = $1, github_login = $2 WHERE id = $3`,
		githubID, githubLogin, userID,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
