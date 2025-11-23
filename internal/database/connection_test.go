package database

import (
	"context"
	"os"
	"testing"
	"time"
)

// getTestDatabaseConfig returns database config for testing
// Reads from DATABASE_URL env var, or uses default test database
func getTestDatabaseConfig() *Config {
	host := os.Getenv("POSTGRES_HOST")
	if host == "" {
		host = "localhost"
	}

	port := os.Getenv("POSTGRES_PORT")
	if port == "" {
		port = "5432"
	}

	user := os.Getenv("POSTGRES_USER")
	if user == "" {
		user = "postgres"
	}

	password := os.Getenv("POSTGRES_PASSWORD")
	if password == "" {
		password = "postgres"
	}

	database := os.Getenv("POSTGRES_DB")
	if database == "" {
		database = "roxas_test"
	}

	return &Config{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
		Database: database,
		SSLMode:  "disable",
	}
}

func TestNewPool_ValidConfig(t *testing.T) {
	// Skip if running in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := getTestDatabaseConfig()

	// Test creating connection pool
	pool, err := NewPool(ctx, cfg)
	if err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer pool.Close()

	// Test ping
	if err := pool.Ping(ctx); err != nil {
		t.Errorf("Failed to ping database: %v", err)
	}

	// Test executing a simple query
	var result int
	err = pool.QueryRow(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		t.Errorf("Failed to execute query: %v", err)
	}
	if result != 1 {
		t.Errorf("Query result = %d, want 1", result)
	}
}

func TestNewPool_InvalidConfig(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name   string
		config *Config
	}{
		{
			name: "missing host",
			config: &Config{
				Port:     "5432",
				User:     "testuser",
				Password: "testpass",
				Database: "testdb",
			},
		},
		{
			name: "missing port",
			config: &Config{
				Host:     "localhost",
				User:     "testuser",
				Password: "testpass",
				Database: "testdb",
			},
		},
		{
			name: "invalid connection string",
			config: &Config{
				Host:     "nonexistent-host-12345",
				Port:     "5432",
				User:     "testuser",
				Password: "testpass",
				Database: "testdb",
				SSLMode:  "disable",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			_, err := NewPool(ctx, tt.config)
			if err == nil {
				t.Error("Expected error for invalid config, got nil")
			}
		})
	}
}

func TestPool_ConnectionPooling(t *testing.T) {
	// Skip if running in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	cfg := getTestDatabaseConfig()

	pool, err := NewPool(ctx, cfg)
	if err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer pool.Close()

	// Test multiple concurrent connections
	numQueries := 20
	errChan := make(chan error, numQueries)

	for i := 0; i < numQueries; i++ {
		go func(id int) {
			var result int
			err := pool.QueryRow(ctx, "SELECT $1", id).Scan(&result)
			if err != nil {
				errChan <- err
				return
			}
			if result != id {
				t.Errorf("Query result = %d, want %d", result, id)
			}
			errChan <- nil
		}(i)
	}

	// Wait for all queries to complete
	for i := 0; i < numQueries; i++ {
		if err := <-errChan; err != nil {
			t.Errorf("Query %d failed: %v", i, err)
		}
	}

	// Verify pool stats
	stats := pool.Stat()
	if stats.TotalConns() == 0 {
		t.Error("Pool has no connections")
	}
	if stats.TotalConns() > 10 {
		t.Errorf("Pool has too many connections: %d, max should be 10", stats.TotalConns())
	}

	t.Logf("Pool stats: total=%d idle=%d", stats.TotalConns(), stats.IdleConns())
}

func TestPool_Close(t *testing.T) {
	// Skip if running in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	cfg := getTestDatabaseConfig()

	pool, err := NewPool(ctx, cfg)
	if err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}

	// Verify pool is working
	if err := pool.Ping(ctx); err != nil {
		t.Errorf("Failed to ping before close: %v", err)
	}

	// Close the pool
	pool.Close()

	// Verify pool is closed (ping should fail)
	if err := pool.Ping(ctx); err == nil {
		t.Error("Expected ping to fail after close, but it succeeded")
	}
}

func TestPool_QueryTimeout(t *testing.T) {
	// Skip if running in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	cfg := getTestDatabaseConfig()

	pool, err := NewPool(ctx, cfg)
	if err != nil {
		t.Skipf("Skipping test: database not available: %v", err)
	}
	defer pool.Close()

	// Test query with timeout
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	// This query should timeout
	_, err = pool.Exec(ctx, "SELECT pg_sleep(1)")
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
}
