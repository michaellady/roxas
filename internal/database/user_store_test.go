package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mikelady/roxas/internal/handlers"
)

func TestNewUserStore(t *testing.T) {
	store := NewUserStore(nil)
	if store == nil {
		t.Error("NewUserStore() returned nil")
	}
}

func TestUserStore_CreateUser(t *testing.T) {
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
	_, err = pool.Exec(ctx, "DELETE FROM users WHERE email LIKE 'test-userstore-%'")
	if err != nil {
		t.Fatalf("Failed to clean users table: %v", err)
	}

	store := NewUserStore(pool)

	tests := []struct {
		name         string
		email        string
		passwordHash string
		wantErr      bool
	}{
		{
			name:         "valid user creation",
			email:        "test-userstore-create@example.com",
			passwordHash: "hashedpassword123",
			wantErr:      false,
		},
		{
			name:         "valid user with special characters in email",
			email:        "test-userstore-special+tag@example.com",
			passwordHash: "hashedpassword456",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := store.CreateUser(ctx, tt.email, tt.passwordHash)

			if tt.wantErr {
				if err == nil {
					t.Error("CreateUser() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("CreateUser() unexpected error: %v", err)
				return
			}

			if user == nil {
				t.Error("CreateUser() returned nil user")
				return
			}

			if user.ID == "" {
				t.Error("CreateUser() returned user with empty ID")
			}
			if user.Email != tt.email {
				t.Errorf("CreateUser() email = %s, want %s", user.Email, tt.email)
			}
			if user.PasswordHash != tt.passwordHash {
				t.Errorf("CreateUser() passwordHash = %s, want %s", user.PasswordHash, tt.passwordHash)
			}
			if user.CreatedAt.IsZero() {
				t.Error("CreateUser() returned user with zero CreatedAt")
			}
			if user.UpdatedAt.IsZero() {
				t.Error("CreateUser() returned user with zero UpdatedAt")
			}
		})
	}
}

func TestUserStore_CreateUser_DuplicateEmail(t *testing.T) {
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
	_, err = pool.Exec(ctx, "DELETE FROM users WHERE email = 'test-userstore-duplicate@example.com'")
	if err != nil {
		t.Fatalf("Failed to clean users table: %v", err)
	}

	store := NewUserStore(pool)
	email := "test-userstore-duplicate@example.com"

	// Create first user
	user1, err := store.CreateUser(ctx, email, "password1")
	if err != nil {
		t.Fatalf("Failed to create first user: %v", err)
	}
	if user1 == nil {
		t.Fatal("First CreateUser() returned nil user")
	}

	// Attempt to create second user with same email
	user2, err := store.CreateUser(ctx, email, "password2")
	if err == nil {
		t.Error("CreateUser() should return error for duplicate email")
	}
	if !errors.Is(err, handlers.ErrDuplicateEmail) {
		t.Errorf("CreateUser() error = %v, want %v", err, handlers.ErrDuplicateEmail)
	}
	if user2 != nil {
		t.Error("CreateUser() should return nil user for duplicate email")
	}
}

func TestUserStore_GetUserByEmail(t *testing.T) {
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
	_, err = pool.Exec(ctx, "DELETE FROM users WHERE email LIKE 'test-userstore-get%'")
	if err != nil {
		t.Fatalf("Failed to clean users table: %v", err)
	}

	store := NewUserStore(pool)

	// Create a test user first
	testEmail := "test-userstore-get@example.com"
	testPasswordHash := "hashedpassword789"
	createdUser, err := store.CreateUser(ctx, testEmail, testPasswordHash)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tests := []struct {
		name      string
		email     string
		wantNil   bool
		wantEmail string
	}{
		{
			name:      "existing user",
			email:     testEmail,
			wantNil:   false,
			wantEmail: testEmail,
		},
		{
			name:    "non-existent user",
			email:   "test-userstore-getnonexistent@example.com",
			wantNil: true,
		},
		{
			name:    "empty email",
			email:   "",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := store.GetUserByEmail(ctx, tt.email)

			if err != nil {
				t.Errorf("GetUserByEmail() unexpected error: %v", err)
				return
			}

			if tt.wantNil {
				if user != nil {
					t.Error("GetUserByEmail() expected nil user, got non-nil")
				}
				return
			}

			if user == nil {
				t.Error("GetUserByEmail() returned nil user, expected non-nil")
				return
			}

			if user.ID != createdUser.ID {
				t.Errorf("GetUserByEmail() ID = %s, want %s", user.ID, createdUser.ID)
			}
			if user.Email != tt.wantEmail {
				t.Errorf("GetUserByEmail() Email = %s, want %s", user.Email, tt.wantEmail)
			}
			if user.PasswordHash != testPasswordHash {
				t.Errorf("GetUserByEmail() PasswordHash = %s, want %s", user.PasswordHash, testPasswordHash)
			}
			if user.CreatedAt.IsZero() {
				t.Error("GetUserByEmail() returned user with zero CreatedAt")
			}
			if user.UpdatedAt.IsZero() {
				t.Error("GetUserByEmail() returned user with zero UpdatedAt")
			}
		})
	}
}

func TestUserStore_ErrorTypes(t *testing.T) {
	// Test that ErrDuplicateEmail is properly defined
	if handlers.ErrDuplicateEmail == nil {
		t.Error("ErrDuplicateEmail should be defined")
	}

	// Test that error can be compared with errors.Is
	if !errors.Is(handlers.ErrDuplicateEmail, handlers.ErrDuplicateEmail) {
		t.Error("ErrDuplicateEmail should be comparable with errors.Is")
	}
}
