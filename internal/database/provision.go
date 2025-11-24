package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// EnsureDatabaseExists connects to the postgres database and creates the target database if it doesn't exist.
// This is used for PR environments where databases are created on-demand on a shared RDS instance.
func EnsureDatabaseExists(ctx context.Context, cfg *Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// Connect to the default postgres database (always exists)
	postgresConnString := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=postgres sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.SSLMode,
	)

	conn, err := pgx.Connect(ctx, postgresConnString)
	if err != nil {
		return fmt.Errorf("failed to connect to postgres database: %w", err)
	}
	defer conn.Close(ctx)

	// Check if the target database exists
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)"
	err = conn.QueryRow(ctx, query, cfg.Database).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if database exists: %w", err)
	}

	// Create the database if it doesn't exist
	if !exists {
		// Note: Database names cannot be parameterized in PostgreSQL
		// We validate the database name format to prevent SQL injection
		if err := validateDatabaseName(cfg.Database); err != nil {
			return fmt.Errorf("invalid database name: %w", err)
		}

		createSQL := fmt.Sprintf("CREATE DATABASE %s OWNER %s", pgx.Identifier{cfg.Database}.Sanitize(), pgx.Identifier{cfg.User}.Sanitize())
		_, err = conn.Exec(ctx, createSQL)
		if err != nil {
			return fmt.Errorf("failed to create database %s: %w", cfg.Database, err)
		}

		fmt.Printf("Successfully created database: %s\n", cfg.Database)
	} else {
		fmt.Printf("Database %s already exists\n", cfg.Database)
	}

	return nil
}

// validateDatabaseName checks if a database name is safe to use in SQL
// PostgreSQL identifiers must start with a letter or underscore and contain only alphanumeric characters and underscores
func validateDatabaseName(name string) error {
	if name == "" {
		return fmt.Errorf("database name cannot be empty")
	}

	// Check first character (must be letter or underscore)
	first := rune(name[0])
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_') {
		return fmt.Errorf("database name must start with a letter or underscore")
	}

	// Check remaining characters (alphanumeric or underscore)
	for _, ch := range name {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_') {
			return fmt.Errorf("database name can only contain letters, numbers, and underscores")
		}
	}

	return nil
}
