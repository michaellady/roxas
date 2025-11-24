package database

import (
	"embed"
	"fmt"
	"net/url"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*
var migrationsFS embed.FS

// RunMigrations executes all pending database migrations
// Returns nil if migrations complete successfully or if there are no migrations to run
func RunMigrations(pool *Pool) error {
	if pool == nil {
		return fmt.Errorf("database pool is nil")
	}

	// Create iofs source driver from embedded filesystem
	sourceDriver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("failed to create migration source: %w", err)
	}

	// Get the underlying connection string from the pool
	// We need to construct the database URL for migrate
	config := pool.Config()

	// Build database URL in the format: pgx5://user:password@host:port/database
	// URL-encode username and password to handle special characters
	dbURL := fmt.Sprintf(
		"pgx5://%s:%s@%s:%d/%s?sslmode=%s",
		url.QueryEscape(config.ConnConfig.User),
		url.QueryEscape(config.ConnConfig.Password),
		config.ConnConfig.Host,
		config.ConnConfig.Port,
		config.ConnConfig.Database,
		"require", // Always require SSL for production
	)

	// Create migrate instance
	m, err := migrate.NewWithSourceInstance("iofs", sourceDriver, dbURL)
	if err != nil {
		return fmt.Errorf("failed to create migration instance: %w", err)
	}
	defer m.Close()

	// Run migrations
	if err := m.Up(); err != nil {
		if err == migrate.ErrNoChange {
			// No migrations to run - this is not an error
			return nil
		}
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}
