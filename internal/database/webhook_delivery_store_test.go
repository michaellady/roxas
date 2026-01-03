package database

import (
	"context"
	"testing"
	"time"

	"github.com/mikelady/roxas/internal/handlers"
)

func TestWebhookDeliveryStore_RecordAndRetrieve(t *testing.T) {
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
	_, _ = pool.Exec(ctx, "DELETE FROM webhook_deliveries")
	_, _ = pool.Exec(ctx, "DELETE FROM repositories")
	_, _ = pool.Exec(ctx, "DELETE FROM users")

	// Create test user and repository
	var userID, repoID string
	err = pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`,
		"test-webhook-delivery@example.com", "hashedpassword",
	).Scan(&userID)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	err = pool.QueryRow(ctx,
		`INSERT INTO repositories (user_id, github_url, webhook_secret) VALUES ($1, $2, $3) RETURNING id`,
		userID, "https://github.com/test/webhook-delivery-test", "testsecret",
	).Scan(&repoID)
	if err != nil {
		t.Fatalf("Failed to create test repository: %v", err)
	}

	store := NewWebhookDeliveryStore(pool)

	t.Run("RecordDelivery creates delivery record", func(t *testing.T) {
		delivery := &handlers.WebhookDelivery{
			RepositoryID: repoID,
			EventType:    "push",
			Payload:      `{"commits": []}`,
			ResponseCode: 200,
			ResponseBody: `{"status": "ok"}`,
			Success:      true,
			DeliveredAt:  time.Now(),
		}

		err := store.RecordDelivery(ctx, delivery)
		if err != nil {
			t.Fatalf("RecordDelivery() error = %v", err)
		}

		if delivery.ID == "" {
			t.Error("RecordDelivery() should set delivery.ID")
		}
	})

	t.Run("GetDelivery retrieves by ID", func(t *testing.T) {
		delivery := &handlers.WebhookDelivery{
			RepositoryID: repoID,
			EventType:    "ping",
			Payload:      `{}`,
			ResponseCode: 200,
			ResponseBody: `{"status": "pong"}`,
			Success:      true,
			DeliveredAt:  time.Now(),
		}

		err := store.RecordDelivery(ctx, delivery)
		if err != nil {
			t.Fatalf("RecordDelivery() error = %v", err)
		}

		got, err := store.GetDelivery(ctx, delivery.ID)
		if err != nil {
			t.Fatalf("GetDelivery() error = %v", err)
		}

		if got.ID != delivery.ID {
			t.Errorf("GetDelivery().ID = %s, want %s", got.ID, delivery.ID)
		}
		if got.EventType != "ping" {
			t.Errorf("GetDelivery().EventType = %s, want ping", got.EventType)
		}
		if !got.Success {
			t.Error("GetDelivery().Success = false, want true")
		}
	})

	t.Run("GetDelivery returns nil for non-existent ID", func(t *testing.T) {
		got, err := store.GetDelivery(ctx, "00000000-0000-0000-0000-000000000000")
		if err != nil {
			t.Fatalf("GetDelivery() error = %v", err)
		}
		if got != nil {
			t.Error("GetDelivery() should return nil for non-existent ID")
		}
	})

	t.Run("RecordDelivery handles failed delivery", func(t *testing.T) {
		delivery := handlers.NewFailedDelivery(
			repoID,
			"push",
			`{"bad": "payload"}`,
			400,
			"invalid signature",
		)

		err := store.RecordDelivery(ctx, delivery)
		if err != nil {
			t.Fatalf("RecordDelivery() error = %v", err)
		}

		got, err := store.GetDelivery(ctx, delivery.ID)
		if err != nil {
			t.Fatalf("GetDelivery() error = %v", err)
		}

		if got.Success {
			t.Error("Failed delivery should have Success = false")
		}
		if got.ErrorMessage != "invalid signature" {
			t.Errorf("ErrorMessage = %s, want 'invalid signature'", got.ErrorMessage)
		}
		if got.ResponseCode != 400 {
			t.Errorf("ResponseCode = %d, want 400", got.ResponseCode)
		}
	})
}

func TestWebhookDeliveryStore_ListDeliveries(t *testing.T) {
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
	_, _ = pool.Exec(ctx, "DELETE FROM webhook_deliveries")
	_, _ = pool.Exec(ctx, "DELETE FROM repositories")
	_, _ = pool.Exec(ctx, "DELETE FROM users")

	// Create test user and two repositories
	var userID, repo1ID, repo2ID string
	err = pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`,
		"test-list-deliveries@example.com", "hashedpassword",
	).Scan(&userID)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	err = pool.QueryRow(ctx,
		`INSERT INTO repositories (user_id, github_url, webhook_secret) VALUES ($1, $2, $3) RETURNING id`,
		userID, "https://github.com/test/repo1-list", "secret1",
	).Scan(&repo1ID)
	if err != nil {
		t.Fatalf("Failed to create test repository 1: %v", err)
	}

	err = pool.QueryRow(ctx,
		`INSERT INTO repositories (user_id, github_url, webhook_secret) VALUES ($1, $2, $3) RETURNING id`,
		userID, "https://github.com/test/repo2-list", "secret2",
	).Scan(&repo2ID)
	if err != nil {
		t.Fatalf("Failed to create test repository 2: %v", err)
	}

	store := NewWebhookDeliveryStore(pool)

	// Create deliveries for repo1
	for i := 0; i < 5; i++ {
		delivery := handlers.NewWebhookDelivery(repo1ID, "push", "{}", 200, "{}", true)
		if err := store.RecordDelivery(ctx, delivery); err != nil {
			t.Fatalf("Failed to create delivery: %v", err)
		}
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	// Create deliveries for repo2
	for i := 0; i < 3; i++ {
		delivery := handlers.NewWebhookDelivery(repo2ID, "ping", "{}", 200, "{}", true)
		if err := store.RecordDelivery(ctx, delivery); err != nil {
			t.Fatalf("Failed to create delivery: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Run("ListDeliveriesForRepository returns correct count", func(t *testing.T) {
		deliveries, err := store.ListDeliveriesForRepository(ctx, repo1ID, 10)
		if err != nil {
			t.Fatalf("ListDeliveriesForRepository() error = %v", err)
		}

		if len(deliveries) != 5 {
			t.Errorf("ListDeliveriesForRepository() returned %d deliveries, want 5", len(deliveries))
		}
	})

	t.Run("ListDeliveriesForRepository respects limit", func(t *testing.T) {
		deliveries, err := store.ListDeliveriesForRepository(ctx, repo1ID, 3)
		if err != nil {
			t.Fatalf("ListDeliveriesForRepository() error = %v", err)
		}

		if len(deliveries) != 3 {
			t.Errorf("ListDeliveriesForRepository() returned %d deliveries, want 3", len(deliveries))
		}
	})

	t.Run("ListDeliveriesForRepository orders by delivered_at DESC", func(t *testing.T) {
		deliveries, err := store.ListDeliveriesForRepository(ctx, repo1ID, 10)
		if err != nil {
			t.Fatalf("ListDeliveriesForRepository() error = %v", err)
		}

		for i := 1; i < len(deliveries); i++ {
			if deliveries[i-1].DeliveredAt.Before(deliveries[i].DeliveredAt) {
				t.Error("Deliveries should be ordered by delivered_at DESC")
				break
			}
		}
	})

	t.Run("GetRecentDeliveries returns from all repositories", func(t *testing.T) {
		deliveries, err := store.GetRecentDeliveries(ctx, 10)
		if err != nil {
			t.Fatalf("GetRecentDeliveries() error = %v", err)
		}

		if len(deliveries) != 8 { // 5 + 3
			t.Errorf("GetRecentDeliveries() returned %d deliveries, want 8", len(deliveries))
		}
	})

	t.Run("GetRecentDeliveries respects limit", func(t *testing.T) {
		deliveries, err := store.GetRecentDeliveries(ctx, 5)
		if err != nil {
			t.Fatalf("GetRecentDeliveries() error = %v", err)
		}

		if len(deliveries) != 5 {
			t.Errorf("GetRecentDeliveries() returned %d deliveries, want 5", len(deliveries))
		}
	})
}

func TestWebhookDeliveryStore_DeleteOldDeliveries(t *testing.T) {
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
	_, _ = pool.Exec(ctx, "DELETE FROM webhook_deliveries")
	_, _ = pool.Exec(ctx, "DELETE FROM repositories")
	_, _ = pool.Exec(ctx, "DELETE FROM users")

	// Create test user and repository
	var userID, repoID string
	err = pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`,
		"test-delete-old@example.com", "hashedpassword",
	).Scan(&userID)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	err = pool.QueryRow(ctx,
		`INSERT INTO repositories (user_id, github_url, webhook_secret) VALUES ($1, $2, $3) RETURNING id`,
		userID, "https://github.com/test/delete-old-test", "secret",
	).Scan(&repoID)
	if err != nil {
		t.Fatalf("Failed to create test repository: %v", err)
	}

	store := NewWebhookDeliveryStore(pool)

	// Insert an old delivery directly with SQL
	oldTime := time.Now().Add(-48 * time.Hour)
	_, err = pool.Exec(ctx,
		`INSERT INTO webhook_deliveries (repository_id, event_type, payload, response_code, response_body, success, delivered_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		repoID, "push", "{}", 200, "{}", true, oldTime,
	)
	if err != nil {
		t.Fatalf("Failed to insert old delivery: %v", err)
	}

	// Insert a recent delivery
	recentDelivery := handlers.NewWebhookDelivery(repoID, "push", "{}", 200, "{}", true)
	if err := store.RecordDelivery(ctx, recentDelivery); err != nil {
		t.Fatalf("Failed to create recent delivery: %v", err)
	}

	t.Run("DeleteOldDeliveries removes old entries", func(t *testing.T) {
		deleted, err := store.DeleteOldDeliveries(ctx, 24*time.Hour)
		if err != nil {
			t.Fatalf("DeleteOldDeliveries() error = %v", err)
		}

		if deleted != 1 {
			t.Errorf("DeleteOldDeliveries() deleted %d rows, want 1", deleted)
		}

		// Verify only recent delivery remains
		deliveries, err := store.ListDeliveriesForRepository(ctx, repoID, 10)
		if err != nil {
			t.Fatalf("ListDeliveriesForRepository() error = %v", err)
		}

		if len(deliveries) != 1 {
			t.Errorf("Expected 1 delivery remaining, got %d", len(deliveries))
		}
	})
}

func TestTruncatePayload(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		wantLen  int
		wantTail string
	}{
		{
			name:     "short payload unchanged",
			payload:  "short payload",
			wantLen:  13,
			wantTail: "short payload",
		},
		{
			name:    "long payload truncated",
			payload: string(make([]byte, 100000)),
			wantLen: handlers.MaxPayloadSize + len("...[truncated]"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := handlers.TruncatePayload(tt.payload)
			if len(got) != tt.wantLen && tt.wantLen > 0 {
				t.Errorf("TruncatePayload() len = %d, want %d", len(got), tt.wantLen)
			}
			if tt.wantTail != "" && got != tt.wantTail {
				t.Errorf("TruncatePayload() = %s, want %s", got, tt.wantTail)
			}
		})
	}
}
