package database

import (
	"testing"

	"github.com/pashagolub/pgxmock/v4"
)

// Database Test Infrastructure
//
// This file provides helpers for unit testing database stores using pgxmock.
// Use these patterns to test store methods without requiring a real PostgreSQL database.
//
// ARCHITECTURE:
//
// All stores use the DBTX interface (defined in dbtx.go) which abstracts database operations.
// This allows stores to work with either:
//   - *Pool (production): Real PostgreSQL connection pool
//   - pgxmock.PgxPoolIface (testing): Mock that simulates database behavior
//
// AVAILABLE STORES AND THEIR TEST CONSTRUCTORS:
//
//   Store                    Test Constructor
//   -----                    ----------------
//   ActivityStore            NewActivityStoreWithDB(db DBTX)
//   UserStore                NewUserStoreWithDB(db DBTX)
//   RepositoryStore          NewRepositoryStoreWithDB(db DBTX)
//   DraftStore               NewDraftStoreWithDB(db DBTX)
//   PostStore                NewPostStoreWithDB(db DBTX)
//   CommitStore              NewCommitStoreWithDB(db DBTX)
//   WebhookDeliveryStore     NewWebhookDeliveryStoreWithDB(db DBTX)
//   CredentialStore          NewCredentialStoreWithDB(db DBTX, encryptionKey []byte)
//
// PATTERN OVERVIEW:
//
// 1. Create a mock pool using NewMockPool(t)
// 2. Set expectations for the SQL queries your test will execute
// 3. Create your store using NewXxxStoreWithDB(mock)
// 4. Call the store method
// 5. Assert results and verify all expectations were met (automatic via t.Cleanup)
//
// EXAMPLE:
//
//   func TestUserStore_GetUserByEmail(t *testing.T) {
//       mock := NewMockPool(t)
//       store := NewUserStoreWithDB(mock)
//
//       // Set up expected query
//       rows := pgxmock.NewRows([]string{"id", "email", "password_hash", "created_at", "updated_at"}).
//           AddRow("user-123", "test@example.com", "hash", time.Now(), time.Now())
//       mock.ExpectQuery(`SELECT id, email, password_hash`).
//           WithArgs("test@example.com").
//           WillReturnRows(rows)
//
//       // Execute
//       user, err := store.GetUserByEmail(context.Background(), "test@example.com")
//
//       // Assert
//       require.NoError(t, err)
//       assert.Equal(t, "test@example.com", user.Email)
//   }
//
// QUERY MATCHING:
//
// pgxmock uses regexp matching by default. Use ExpectQuery/ExpectExec with a pattern
// that matches the SQL query. You can use:
//   - Literal strings (will be regexp-escaped automatically by pgxmock)
//   - Regexp patterns for flexible matching
//   - pgxmock.QueryMatcherEqual for exact string matching
//
// COMMON PATTERNS:
//
// - Testing not found: Return pgx.ErrNoRows or empty rows
// - Testing errors: Use WillReturnError(err)
// - Testing constraint violations: Return a *pgconn.PgError with appropriate code
// - Testing multiple rows: Use AddRow() multiple times on the same Rows object
//
// HANDLING NIL POINTER ARGUMENTS:
//
// When store methods accept optional pointer arguments (*string, etc.), pgxmock's
// argument matching can be tricky with nil values. Use pgxmock.AnyArg() for
// optional parameters you don't want to match exactly:
//
//   mock.ExpectQuery(`INSERT INTO...`).
//       WithArgs(userID, activityType, pgxmock.AnyArg(), pgxmock.AnyArg()).
//       WillReturnRows(rows)
//
// See activity_store_mock_test.go for complete examples.

// NewMockPool creates a new pgxmock pool for testing.
// The mock is automatically configured with QueryMatcherRegexp for flexible query matching.
// Call mock.ExpectationsWereMet() at the end of your test to verify all expectations.
func NewMockPool(t *testing.T) pgxmock.PgxPoolIface {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	t.Cleanup(func() {
		mock.Close()
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled mock expectations: %v", err)
		}
	})
	return mock
}

// NewMockPoolWithQueryMatcher creates a mock pool with a custom query matcher.
// Use pgxmock.QueryMatcherEqual for exact string matching if regexp is not desired.
func NewMockPoolWithQueryMatcher(t *testing.T, matcher pgxmock.QueryMatcher) pgxmock.PgxPoolIface {
	t.Helper()
	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(matcher))
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	t.Cleanup(func() {
		mock.Close()
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled mock expectations: %v", err)
		}
	})
	return mock
}
