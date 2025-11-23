package db

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

// getTestDatabaseURL returns the database URL for testing
// Reads from DATABASE_URL env var, or uses default test database
func getTestDatabaseURL() string {
	if url := os.Getenv("DATABASE_URL"); url != "" {
		return url
	}
	// Default local test database
	return "postgres://postgres:postgres@localhost:5432/roxas_test?sslmode=disable"
}

// TestMigrationsUpDown tests that migrations can be applied and rolled back
func TestMigrationsUpDown(t *testing.T) {
	dbURL := getTestDatabaseURL()

	// Connect to database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("Skipping migration test: database not available: %v", err)
	}
	defer db.Close()

	// Verify connection
	if err := db.Ping(); err != nil {
		t.Skipf("Skipping migration test: cannot ping database: %v", err)
	}

	// Clean up any existing schema
	cleanupDatabase(t, db)

	// Create migrate instance
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		t.Fatalf("Failed to create postgres driver: %v", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres", driver)
	if err != nil {
		t.Fatalf("Failed to create migrate instance: %v", err)
	}

	// Test UP migration
	t.Run("up migration", func(t *testing.T) {
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			t.Fatalf("Failed to run up migration: %v", err)
		}

		// Verify tables exist
		tables := []string{"users", "repositories", "commits", "posts"}
		for _, table := range tables {
			if !tableExists(t, db, table) {
				t.Errorf("Table %s does not exist after migration", table)
			}
		}

		// Verify indexes exist
		indexes := []string{
			"idx_users_email",
			"idx_repositories_user_id",
			"idx_repositories_webhook_secret",
			"idx_commits_repository_id",
			"idx_commits_sha",
			"idx_posts_commit_id",
			"idx_posts_platform",
			"idx_posts_status",
		}
		for _, index := range indexes {
			if !indexExists(t, db, index) {
				t.Errorf("Index %s does not exist after migration", index)
			}
		}

		// Verify foreign keys work by inserting test data
		testForeignKeyConstraints(t, db)
	})

	// Test DOWN migration
	t.Run("down migration", func(t *testing.T) {
		if err := m.Down(); err != nil {
			t.Fatalf("Failed to run down migration: %v", err)
		}

		// Verify tables are dropped
		tables := []string{"users", "repositories", "commits", "posts"}
		for _, table := range tables {
			if tableExists(t, db, table) {
				t.Errorf("Table %s still exists after down migration", table)
			}
		}
	})
}

// tableExists checks if a table exists in the database
func tableExists(t *testing.T, db *sql.DB, tableName string) bool {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_schema = 'public'
			AND table_name = $1
		)
	`
	err := db.QueryRow(query, tableName).Scan(&exists)
	if err != nil {
		t.Logf("Error checking if table %s exists: %v", tableName, err)
		return false
	}
	return exists
}

// indexExists checks if an index exists in the database
func indexExists(t *testing.T, db *sql.DB, indexName string) bool {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT FROM pg_indexes
			WHERE schemaname = 'public'
			AND indexname = $1
		)
	`
	err := db.QueryRow(query, indexName).Scan(&exists)
	if err != nil {
		t.Logf("Error checking if index %s exists: %v", indexName, err)
		return false
	}
	return exists
}

// testForeignKeyConstraints verifies foreign key relationships work correctly
func testForeignKeyConstraints(t *testing.T, db *sql.DB) {
	// Insert a test user
	var userID string
	err := db.QueryRow(`
		INSERT INTO users (email, password_hash)
		VALUES ($1, $2)
		RETURNING id
	`, "test@example.com", "hashed_password").Scan(&userID)
	if err != nil {
		t.Errorf("Failed to insert test user: %v", err)
		return
	}

	// Insert a test repository
	var repoID string
	err = db.QueryRow(`
		INSERT INTO repositories (user_id, github_url, webhook_secret)
		VALUES ($1, $2, $3)
		RETURNING id
	`, userID, "https://github.com/test/repo", "test_secret").Scan(&repoID)
	if err != nil {
		t.Errorf("Failed to insert test repository: %v", err)
		return
	}

	// Insert a test commit
	var commitID string
	err = db.QueryRow(`
		INSERT INTO commits (repository_id, commit_sha, github_url, commit_message, author, timestamp)
		VALUES ($1, $2, $3, $4, $5, NOW())
		RETURNING id
	`, repoID, "abc123", "https://github.com/test/repo/commit/abc123", "Test commit", "Test Author").Scan(&commitID)
	if err != nil {
		t.Errorf("Failed to insert test commit: %v", err)
		return
	}

	// Insert a test post
	var postID string
	err = db.QueryRow(`
		INSERT INTO posts (commit_id, platform, content)
		VALUES ($1, $2, $3)
		RETURNING id
	`, commitID, "linkedin", "Test post content").Scan(&postID)
	if err != nil {
		t.Errorf("Failed to insert test post: %v", err)
		return
	}

	// Verify cascade delete works
	_, err = db.Exec("DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		t.Errorf("Failed to delete test user: %v", err)
		return
	}

	// Verify all related records were deleted
	var count int
	db.QueryRow("SELECT COUNT(*) FROM repositories WHERE id = $1", repoID).Scan(&count)
	if count != 0 {
		t.Errorf("Repository was not cascade deleted")
	}

	db.QueryRow("SELECT COUNT(*) FROM commits WHERE id = $1", commitID).Scan(&count)
	if count != 0 {
		t.Errorf("Commit was not cascade deleted")
	}

	db.QueryRow("SELECT COUNT(*) FROM posts WHERE id = $1", postID).Scan(&count)
	if count != 0 {
		t.Errorf("Post was not cascade deleted")
	}

	t.Log("Foreign key constraints and cascade deletes working correctly")
}

// cleanupDatabase drops all tables to ensure clean test state
func cleanupDatabase(t *testing.T, db *sql.DB) {
	tables := []string{"posts", "commits", "repositories", "users"}
	for _, table := range tables {
		_, err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE", table))
		if err != nil {
			t.Logf("Warning: failed to drop table %s: %v", table, err)
		}
	}

	// Drop trigger function if exists
	db.Exec("DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE")
}
