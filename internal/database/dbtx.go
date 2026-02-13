package database

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DBTX is the interface that both pgxpool.Pool and pgxmock satisfy.
// This allows stores to work with either a real database or a mock for testing.
//
// This interface is intentionally minimal, containing only the methods
// used by the store implementations. Add methods here as needed.
type DBTX interface {
	// Exec executes a query that doesn't return rows (INSERT, UPDATE, DELETE)
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)

	// Query executes a query that returns multiple rows
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)

	// QueryRow executes a query that returns at most one row
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Compile-time check that Pool satisfies DBTX
var _ DBTX = (*Pool)(nil)
