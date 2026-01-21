package database

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Draft represents a draft social media post (TDD: define expected type)
type Draft struct {
	ID               string
	UserID           string
	RepositoryID     string
	Ref              string
	BeforeSHA        string
	AfterSHA         string
	CommitSHAs       []string
	GeneratedContent string
	EditedContent    *string
	Status           string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// DraftStore handles draft persistence (TDD: define expected interface)
type DraftStore struct {
	pool *Pool
}

// NewDraftStore creates a new draft store
func NewDraftStore(pool *Pool) *DraftStore {
	return &DraftStore{pool: pool}
}

// CreateDraft creates a new draft (stub - to be implemented in alice-63)
func (s *DraftStore) CreateDraft(ctx context.Context, userID, repoID, ref, beforeSHA, afterSHA string, commitSHAs []string, content string) (*Draft, error) {
	// TODO: Implement in alice-63
	return nil, errors.New("CreateDraft not implemented")
}

// GetDraft retrieves a draft by ID (stub - to be implemented in alice-63)
func (s *DraftStore) GetDraft(ctx context.Context, draftID string) (*Draft, error) {
	// TODO: Implement in alice-63
	return nil, errors.New("GetDraft not implemented")
}

// ListDraftsByUser lists all drafts for a user (stub - to be implemented in alice-63)
func (s *DraftStore) ListDraftsByUser(ctx context.Context, userID string) ([]*Draft, error) {
	// TODO: Implement in alice-63
	return nil, errors.New("ListDraftsByUser not implemented")
}

// UpdateDraftContent updates the edited content of a draft (stub - to be implemented in alice-63)
func (s *DraftStore) UpdateDraftContent(ctx context.Context, draftID, content string) error {
	// TODO: Implement in alice-63
	return errors.New("UpdateDraftContent not implemented")
}

// UpdateDraftStatus updates the status of a draft (stub - to be implemented in alice-63)
func (s *DraftStore) UpdateDraftStatus(ctx context.Context, draftID, status string) error {
	// TODO: Implement in alice-63
	return errors.New("UpdateDraftStatus not implemented")
}

// DeleteDraft deletes a draft (stub - to be implemented in alice-63)
func (s *DraftStore) DeleteDraft(ctx context.Context, draftID string) error {
	// TODO: Implement in alice-63
	return errors.New("DeleteDraft not implemented")
}

// Draft status constants
const (
	DraftStatusDraft  = "draft"
	DraftStatusPosted = "posted"
	DraftStatusFailed = "failed"
	DraftStatusError  = "error"
)

func TestDraftStore_CreateDraft(t *testing.T) {
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

	if err := RunMigrations(pool); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Clean up test data
	cleanupDraftTestData(t, ctx, pool)

	// Create test user and repository
	userID := createTestUser(t, ctx, pool, "draft-create@example.com")
	repoID := createTestRepository(t, ctx, pool, userID, "https://github.com/test/draft-create-repo")

	store := NewDraftStore(pool)

	tests := []struct {
		name         string
		userID       string
		repoID       string
		ref          string
		beforeSHA    string
		afterSHA     string
		commitSHAs   []string
		content      string
		wantErr      bool
		errSubstring string
	}{
		{
			name:       "create valid draft",
			userID:     userID,
			repoID:     repoID,
			ref:        "refs/heads/main",
			beforeSHA:  "abc123",
			afterSHA:   "def456",
			commitSHAs: []string{"def456"},
			content:    "Generated post content about the commit",
			wantErr:    false,
		},
		{
			name:       "create draft with multiple commits",
			userID:     userID,
			repoID:     repoID,
			ref:        "refs/heads/feature",
			beforeSHA:  "111111",
			afterSHA:   "333333",
			commitSHAs: []string{"222222", "333333"},
			content:    "Post covering multiple commits",
			wantErr:    false,
		},
		{
			name:         "create draft with empty user ID",
			userID:       "",
			repoID:       repoID,
			ref:          "refs/heads/main",
			beforeSHA:    "abc123",
			afterSHA:     "def456",
			commitSHAs:   []string{"def456"},
			content:      "Content",
			wantErr:      true,
			errSubstring: "user_id",
		},
		{
			name:         "create draft with invalid user ID",
			userID:       "00000000-0000-0000-0000-000000000000",
			repoID:       repoID,
			ref:          "refs/heads/main",
			beforeSHA:    "abc123",
			afterSHA:     "def456",
			commitSHAs:   []string{"def456"},
			content:      "Content",
			wantErr:      true,
			errSubstring: "foreign key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			draft, err := store.CreateDraft(ctx, tt.userID, tt.repoID, tt.ref, tt.beforeSHA, tt.afterSHA, tt.commitSHAs, tt.content)

			if tt.wantErr {
				if err == nil {
					t.Errorf("CreateDraft() expected error containing %q, got nil", tt.errSubstring)
				}
				return
			}

			if err != nil {
				t.Errorf("CreateDraft() unexpected error: %v", err)
				return
			}

			if draft.ID == "" {
				t.Error("CreateDraft() returned draft with empty ID")
			}
			if draft.UserID != tt.userID {
				t.Errorf("CreateDraft() UserID = %s, want %s", draft.UserID, tt.userID)
			}
			if draft.Status != DraftStatusDraft {
				t.Errorf("CreateDraft() Status = %s, want %s", draft.Status, DraftStatusDraft)
			}
			if draft.GeneratedContent != tt.content {
				t.Errorf("CreateDraft() GeneratedContent = %s, want %s", draft.GeneratedContent, tt.content)
			}
		})
	}
}

func TestDraftStore_GetDraft(t *testing.T) {
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

	if err := RunMigrations(pool); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	cleanupDraftTestData(t, ctx, pool)

	userID := createTestUser(t, ctx, pool, "draft-get@example.com")
	repoID := createTestRepository(t, ctx, pool, userID, "https://github.com/test/draft-get-repo")

	store := NewDraftStore(pool)

	// Create a draft to retrieve
	created, err := store.CreateDraft(ctx, userID, repoID, "refs/heads/main", "aaa", "bbb", []string{"bbb"}, "Test content")
	if err != nil {
		t.Fatalf("Failed to create test draft: %v", err)
	}

	tests := []struct {
		name    string
		draftID string
		wantErr bool
	}{
		{
			name:    "get existing draft",
			draftID: created.ID,
			wantErr: false,
		},
		{
			name:    "get non-existent draft",
			draftID: "00000000-0000-0000-0000-000000000000",
			wantErr: true,
		},
		{
			name:    "get with invalid UUID",
			draftID: "not-a-uuid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			draft, err := store.GetDraft(ctx, tt.draftID)

			if tt.wantErr {
				if err == nil {
					t.Error("GetDraft() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("GetDraft() unexpected error: %v", err)
				return
			}

			if draft.ID != tt.draftID {
				t.Errorf("GetDraft() ID = %s, want %s", draft.ID, tt.draftID)
			}
		})
	}
}

func TestDraftStore_ListDraftsByUser(t *testing.T) {
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

	if err := RunMigrations(pool); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	cleanupDraftTestData(t, ctx, pool)

	// Create two users with different drafts
	user1ID := createTestUser(t, ctx, pool, "draft-list-user1@example.com")
	user2ID := createTestUser(t, ctx, pool, "draft-list-user2@example.com")
	repo1ID := createTestRepository(t, ctx, pool, user1ID, "https://github.com/test/draft-list-repo1")
	repo2ID := createTestRepository(t, ctx, pool, user2ID, "https://github.com/test/draft-list-repo2")

	store := NewDraftStore(pool)

	// Create drafts for user1
	_, err = store.CreateDraft(ctx, user1ID, repo1ID, "refs/heads/main", "a1", "b1", []string{"b1"}, "User1 Draft 1")
	if err != nil {
		t.Fatalf("Failed to create draft 1: %v", err)
	}
	_, err = store.CreateDraft(ctx, user1ID, repo1ID, "refs/heads/feature", "a2", "b2", []string{"b2"}, "User1 Draft 2")
	if err != nil {
		t.Fatalf("Failed to create draft 2: %v", err)
	}

	// Create draft for user2
	_, err = store.CreateDraft(ctx, user2ID, repo2ID, "refs/heads/main", "c1", "d1", []string{"d1"}, "User2 Draft 1")
	if err != nil {
		t.Fatalf("Failed to create draft 3: %v", err)
	}

	tests := []struct {
		name      string
		userID    string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "list drafts for user1",
			userID:    user1ID,
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:      "list drafts for user2",
			userID:    user2ID,
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "list drafts for non-existent user",
			userID:    "00000000-0000-0000-0000-000000000000",
			wantCount: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			drafts, err := store.ListDraftsByUser(ctx, tt.userID)

			if tt.wantErr {
				if err == nil {
					t.Error("ListDraftsByUser() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ListDraftsByUser() unexpected error: %v", err)
				return
			}

			if len(drafts) != tt.wantCount {
				t.Errorf("ListDraftsByUser() returned %d drafts, want %d", len(drafts), tt.wantCount)
			}

			// Verify all drafts belong to the correct user
			for _, d := range drafts {
				if d.UserID != tt.userID {
					t.Errorf("ListDraftsByUser() returned draft with UserID = %s, want %s", d.UserID, tt.userID)
				}
			}
		})
	}
}

func TestDraftStore_UpdateDraftContent(t *testing.T) {
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

	if err := RunMigrations(pool); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	cleanupDraftTestData(t, ctx, pool)

	userID := createTestUser(t, ctx, pool, "draft-update-content@example.com")
	repoID := createTestRepository(t, ctx, pool, userID, "https://github.com/test/draft-update-content-repo")

	store := NewDraftStore(pool)

	// Create a draft to update
	created, err := store.CreateDraft(ctx, userID, repoID, "refs/heads/main", "aaa", "bbb", []string{"bbb"}, "Original generated content")
	if err != nil {
		t.Fatalf("Failed to create test draft: %v", err)
	}

	tests := []struct {
		name       string
		draftID    string
		newContent string
		wantErr    bool
	}{
		{
			name:       "update content successfully",
			draftID:    created.ID,
			newContent: "User edited content with improvements",
			wantErr:    false,
		},
		{
			name:       "update non-existent draft",
			draftID:    "00000000-0000-0000-0000-000000000000",
			newContent: "Some content",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.UpdateDraftContent(ctx, tt.draftID, tt.newContent)

			if tt.wantErr {
				if err == nil {
					t.Error("UpdateDraftContent() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("UpdateDraftContent() unexpected error: %v", err)
				return
			}

			// Verify the content was updated
			updated, err := store.GetDraft(ctx, tt.draftID)
			if err != nil {
				t.Fatalf("Failed to get updated draft: %v", err)
			}

			if updated.EditedContent == nil || *updated.EditedContent != tt.newContent {
				t.Errorf("UpdateDraftContent() EditedContent = %v, want %s", updated.EditedContent, tt.newContent)
			}
		})
	}
}

func TestDraftStore_UpdateDraftStatus(t *testing.T) {
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

	if err := RunMigrations(pool); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	cleanupDraftTestData(t, ctx, pool)

	userID := createTestUser(t, ctx, pool, "draft-update-status@example.com")
	repoID := createTestRepository(t, ctx, pool, userID, "https://github.com/test/draft-update-status-repo")

	store := NewDraftStore(pool)

	// Create a draft to update
	created, err := store.CreateDraft(ctx, userID, repoID, "refs/heads/main", "aaa", "bbb", []string{"bbb"}, "Content")
	if err != nil {
		t.Fatalf("Failed to create test draft: %v", err)
	}

	tests := []struct {
		name      string
		draftID   string
		newStatus string
		wantErr   bool
	}{
		{
			name:      "update to posted",
			draftID:   created.ID,
			newStatus: DraftStatusPosted,
			wantErr:   false,
		},
		{
			name:      "update to failed",
			draftID:   created.ID,
			newStatus: DraftStatusFailed,
			wantErr:   false,
		},
		{
			name:      "update to error",
			draftID:   created.ID,
			newStatus: DraftStatusError,
			wantErr:   false,
		},
		{
			name:      "update back to draft",
			draftID:   created.ID,
			newStatus: DraftStatusDraft,
			wantErr:   false,
		},
		{
			name:      "invalid status",
			draftID:   created.ID,
			newStatus: "invalid_status",
			wantErr:   true,
		},
		{
			name:      "update non-existent draft",
			draftID:   "00000000-0000-0000-0000-000000000000",
			newStatus: DraftStatusPosted,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.UpdateDraftStatus(ctx, tt.draftID, tt.newStatus)

			if tt.wantErr {
				if err == nil {
					t.Error("UpdateDraftStatus() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("UpdateDraftStatus() unexpected error: %v", err)
				return
			}

			// Verify the status was updated
			updated, err := store.GetDraft(ctx, tt.draftID)
			if err != nil {
				t.Fatalf("Failed to get updated draft: %v", err)
			}

			if updated.Status != tt.newStatus {
				t.Errorf("UpdateDraftStatus() Status = %s, want %s", updated.Status, tt.newStatus)
			}
		})
	}
}

func TestDraftStore_DeleteDraft(t *testing.T) {
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

	if err := RunMigrations(pool); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	cleanupDraftTestData(t, ctx, pool)

	userID := createTestUser(t, ctx, pool, "draft-delete@example.com")
	repoID := createTestRepository(t, ctx, pool, userID, "https://github.com/test/draft-delete-repo")

	store := NewDraftStore(pool)

	// Create a draft to delete
	created, err := store.CreateDraft(ctx, userID, repoID, "refs/heads/main", "aaa", "bbb", []string{"bbb"}, "Content to delete")
	if err != nil {
		t.Fatalf("Failed to create test draft: %v", err)
	}

	tests := []struct {
		name    string
		draftID string
		wantErr bool
	}{
		{
			name:    "delete existing draft",
			draftID: created.ID,
			wantErr: false,
		},
		{
			name:    "delete already deleted draft",
			draftID: created.ID,
			wantErr: true, // Should error on second delete
		},
		{
			name:    "delete non-existent draft",
			draftID: "00000000-0000-0000-0000-000000000000",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.DeleteDraft(ctx, tt.draftID)

			if tt.wantErr {
				if err == nil {
					t.Error("DeleteDraft() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("DeleteDraft() unexpected error: %v", err)
				return
			}

			// Verify the draft was deleted
			_, err = store.GetDraft(ctx, tt.draftID)
			if err == nil {
				t.Error("GetDraft() should return error for deleted draft")
			}
		})
	}
}

// Helper functions for test setup

func cleanupDraftTestData(t *testing.T, ctx context.Context, pool *Pool) {
	t.Helper()
	// Clean up in order respecting foreign keys
	tables := []string{"drafts", "posts", "commits", "webhook_deliveries", "repositories", "users"}
	for _, table := range tables {
		_, err := pool.Exec(ctx, "DELETE FROM "+table)
		if err != nil {
			// Table might not exist yet, that's ok
			t.Logf("Note: could not clean %s: %v", table, err)
		}
	}
}

func createTestUser(t *testing.T, ctx context.Context, pool *Pool, email string) string {
	t.Helper()
	var userID string
	err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`,
		email, "hashedpassword",
	).Scan(&userID)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	return userID
}

func createTestRepository(t *testing.T, ctx context.Context, pool *Pool, userID, githubURL string) string {
	t.Helper()
	var repoID string
	err := pool.QueryRow(ctx,
		`INSERT INTO repositories (user_id, github_url, webhook_secret) VALUES ($1, $2, $3) RETURNING id`,
		userID, githubURL, "testsecret123",
	).Scan(&repoID)
	if err != nil {
		t.Fatalf("Failed to create test repository: %v", err)
	}
	return repoID
}
