package database

import (
	"embed"
	"fmt"
	"log"
	"net/url"
	"strings"

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

	// Build database URL using url.URL to properly handle special characters in credentials
	u := &url.URL{
		Scheme: "pgx5",
		User:   url.UserPassword(config.ConnConfig.User, config.ConnConfig.Password),
		Host:   fmt.Sprintf("%s:%d", config.ConnConfig.Host, config.ConnConfig.Port),
		Path:   "/" + config.ConnConfig.Database,
		RawQuery: "sslmode=require",
	}
	dbURL := u.String()

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

		// Check for dirty database error and attempt recovery
		if strings.Contains(err.Error(), "Dirty database") {
			log.Printf("Detected dirty database state, attempting recovery...")

			// Get current version to understand the state
			version, dirty, verr := m.Version()
			if verr != nil {
				return fmt.Errorf("failed to get migration version: %w (original error: %v)", verr, err)
			}

			if dirty {
				log.Printf("Database is dirty at version %d, forcing to previous version", version)

				// Force to previous clean version
				if ferr := m.Force(int(version) - 1); ferr != nil {
					return fmt.Errorf("failed to force migration version: %w (original error: %v)", ferr, err)
				}

				// Retry migrations
				log.Printf("Retrying migrations after recovery...")
				if rerr := m.Up(); rerr != nil {
					if rerr == migrate.ErrNoChange {
						return nil
					}
					return fmt.Errorf("failed to run migrations after recovery: %w", rerr)
				}

				log.Printf("Migration recovery successful")
				return nil
			}
		}

		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}
