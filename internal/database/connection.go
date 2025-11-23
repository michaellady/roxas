package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool wraps pgxpool.Pool with additional configuration
type Pool struct {
	*pgxpool.Pool
}

// NewPool creates a new connection pool with the given configuration
func NewPool(ctx context.Context, cfg *Config) (*Pool, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Build connection string
	connString := cfg.ConnectionString()

	// Parse connection config
	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Configure connection pool settings
	poolConfig.MaxConns = 10                              // Maximum connections
	poolConfig.MinConns = 2                               // Minimum idle connections
	poolConfig.MaxConnLifetime = 30 * time.Minute         // Max connection lifetime
	poolConfig.MaxConnIdleTime = 5 * time.Minute          // Max idle time
	poolConfig.HealthCheckPeriod = 1 * time.Minute        // Health check interval
	poolConfig.ConnConfig.ConnectTimeout = 10 * time.Second // Connection timeout

	// Create the pool
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Verify connection by pinging the database
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Pool{Pool: pool}, nil
}

// Close gracefully closes the connection pool
func (p *Pool) Close() {
	if p.Pool != nil {
		p.Pool.Close()
	}
}
