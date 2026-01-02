package database

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPostStore_UpdatePostStatus(t *testing.T) {
	// Skip if running in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := getTestDatabaseConfig()

	pool, err := NewPool(ctx, cfg)
	if err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer pool.Close()

	// Run migrations to ensure tables exist
	if err := RunMigrations(pool); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Clean up test data (order matters due to foreign keys)
	_, err = pool.Exec(ctx, "DELETE FROM posts")
	if err != nil {
		t.Fatalf("Failed to clean posts table: %v", err)
	}
	_, err = pool.Exec(ctx, "DELETE FROM commits")
	if err != nil {
		t.Fatalf("Failed to clean commits table: %v", err)
	}
	_, err = pool.Exec(ctx, "DELETE FROM repositories")
	if err != nil {
		t.Fatalf("Failed to clean repositories table: %v", err)
	}
	_, err = pool.Exec(ctx, "DELETE FROM users")
	if err != nil {
		t.Fatalf("Failed to clean users table: %v", err)
	}

	// Create test user
	var userID string
	err = pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`,
		"test-poststatus@example.com", "hashedpassword",
	).Scan(&userID)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create test repository
	var repoID string
	err = pool.QueryRow(ctx,
		`INSERT INTO repositories (user_id, github_url, webhook_secret) VALUES ($1, $2, $3) RETURNING id`,
		userID, "https://github.com/test/repo-poststatus", "testsecret123poststatus",
	).Scan(&repoID)
	if err != nil {
		t.Fatalf("Failed to create test repository: %v", err)
	}

	// Create test commit
	var commitID string
	err = pool.QueryRow(ctx,
		`INSERT INTO commits (repository_id, commit_sha, github_url, commit_message, author, timestamp)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		repoID, "abc123def456poststatus", "https://github.com/test/repo/commit/abc123", "Test commit", "tester", time.Now(),
	).Scan(&commitID)
	if err != nil {
		t.Fatalf("Failed to create test commit: %v", err)
	}

	// Create test post with initial status 'draft'
	var postID string
	err = pool.QueryRow(ctx,
		`INSERT INTO posts (commit_id, platform, content, status) VALUES ($1, $2, $3, $4) RETURNING id`,
		commitID, "linkedin", "Test post content", "draft",
	).Scan(&postID)
	if err != nil {
		t.Fatalf("Failed to create test post: %v", err)
	}

	postStore := NewPostStore(pool)

	tests := []struct {
		name      string
		postID    string
		newStatus string
		wantErr   bool
	}{
		{
			name:      "update draft to posted",
			postID:    postID,
			newStatus: "posted",
			wantErr:   false,
		},
		{
			name:      "update posted to failed",
			postID:    postID,
			newStatus: "failed",
			wantErr:   false,
		},
		{
			name:      "update failed back to draft",
			postID:    postID,
			newStatus: "draft",
			wantErr:   false,
		},
		{
			name:      "invalid status",
			postID:    postID,
			newStatus: "invalid_status",
			wantErr:   true,
		},
		{
			name:      "non-existent post",
			postID:    "00000000-0000-0000-0000-000000000000",
			newStatus: "posted",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := postStore.UpdatePostStatus(ctx, tt.postID, tt.newStatus)

			if tt.wantErr {
				if err == nil {
					t.Errorf("UpdatePostStatus() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("UpdatePostStatus() unexpected error: %v", err)
				return
			}

			// Verify the status was actually updated
			var actualStatus string
			err = pool.QueryRow(ctx, "SELECT status FROM posts WHERE id = $1", tt.postID).Scan(&actualStatus)
			if err != nil {
				t.Errorf("Failed to verify status: %v", err)
				return
			}
			if actualStatus != tt.newStatus {
				t.Errorf("Status = %s, want %s", actualStatus, tt.newStatus)
			}
		})
	}
}

func TestPostStore_UpdatePostStatus_ErrorTypes(t *testing.T) {
	// Test that ErrPostNotFound and ErrInvalidStatus are properly defined
	if ErrPostNotFound == nil {
		t.Error("ErrPostNotFound should be defined")
	}
	if ErrInvalidStatus == nil {
		t.Error("ErrInvalidStatus should be defined")
	}

	// Test that errors can be compared with errors.Is
	if !errors.Is(ErrPostNotFound, ErrPostNotFound) {
		t.Error("ErrPostNotFound should be comparable with errors.Is")
	}
	if !errors.Is(ErrInvalidStatus, ErrInvalidStatus) {
		t.Error("ErrInvalidStatus should be comparable with errors.Is")
	}
}
