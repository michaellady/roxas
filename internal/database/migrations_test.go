package database

import (
	"testing"
)

func TestRunMigrations_NilPool(t *testing.T) {
	err := RunMigrations(nil)
	if err == nil {
		t.Error("Expected error when pool is nil, got nil")
	}
	if err.Error() != "database pool is nil" {
		t.Errorf("Expected 'database pool is nil' error, got: %v", err)
	}
}

// Note: Integration tests for actual migrations would require a test database
// For now, we're testing the error handling for nil pool
// Full migration testing should be done in E2E tests with a real database
