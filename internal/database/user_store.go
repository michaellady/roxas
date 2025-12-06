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
	pool *Pool
}

// NewUserStore creates a new database-backed user store
func NewUserStore(pool *Pool) *UserStore {
	return &UserStore{pool: pool}
}

// CreateUser creates a new user in the database
func (s *UserStore) CreateUser(ctx context.Context, email, passwordHash string) (*handlers.User, error) {
	var user handlers.User
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash)
		 VALUES ($1, $2)
		 RETURNING id, email, password_hash, created_at, updated_at`,
		email, passwordHash,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		// Check for unique constraint violation (duplicate email)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, handlers.ErrDuplicateEmail
		}
		return nil, err
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email address
func (s *UserStore) GetUserByEmail(ctx context.Context, email string) (*handlers.User, error) {
	var user handlers.User
	var createdAt, updatedAt time.Time

	err := s.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, created_at, updated_at
		 FROM users
		 WHERE email = $1`,
		email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &createdAt, &updatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // User not found - return nil, nil per interface contract
		}
		return nil, err
	}

	user.CreatedAt = createdAt
	user.UpdatedAt = updatedAt
	return &user, nil
}
