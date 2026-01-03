package database

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mikelady/roxas/internal/handlers"
)

// Compile-time interface compliance check
var _ handlers.WebhookDeliveryStore = (*WebhookDeliveryStore)(nil)

// WebhookDeliveryStore implements handlers.WebhookDeliveryStore using PostgreSQL
type WebhookDeliveryStore struct {
	pool *Pool
}

// NewWebhookDeliveryStore creates a new database-backed webhook delivery store
func NewWebhookDeliveryStore(pool *Pool) *WebhookDeliveryStore {
	return &WebhookDeliveryStore{pool: pool}
}

// RecordDelivery stores a webhook delivery attempt
func (s *WebhookDeliveryStore) RecordDelivery(ctx context.Context, delivery *handlers.WebhookDelivery) error {
	// Truncate payload if too large
	payload := handlers.TruncatePayload(delivery.Payload)

	err := s.pool.QueryRow(ctx,
		`INSERT INTO webhook_deliveries
		 (repository_id, event_type, payload, response_code, response_body, success, error_message, delivered_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id`,
		delivery.RepositoryID,
		delivery.EventType,
		payload,
		delivery.ResponseCode,
		delivery.ResponseBody,
		delivery.Success,
		delivery.ErrorMessage,
		delivery.DeliveredAt,
	).Scan(&delivery.ID)

	return err
}

// GetDelivery retrieves a specific delivery by ID
func (s *WebhookDeliveryStore) GetDelivery(ctx context.Context, deliveryID string) (*handlers.WebhookDelivery, error) {
	var delivery handlers.WebhookDelivery

	err := s.pool.QueryRow(ctx,
		`SELECT id, repository_id, event_type, payload, response_code, response_body,
		        success, error_message, delivered_at
		 FROM webhook_deliveries
		 WHERE id = $1`,
		deliveryID,
	).Scan(
		&delivery.ID,
		&delivery.RepositoryID,
		&delivery.EventType,
		&delivery.Payload,
		&delivery.ResponseCode,
		&delivery.ResponseBody,
		&delivery.Success,
		&delivery.ErrorMessage,
		&delivery.DeliveredAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &delivery, nil
}

// ListDeliveriesForRepository retrieves recent deliveries for a repository
func (s *WebhookDeliveryStore) ListDeliveriesForRepository(ctx context.Context, repoID string, limit int) ([]*handlers.WebhookDelivery, error) {
	if limit <= 0 {
		limit = 50 // Default limit
	}
	if limit > 1000 {
		limit = 1000 // Max limit
	}

	rows, err := s.pool.Query(ctx,
		`SELECT id, repository_id, event_type, payload, response_code, response_body,
		        success, error_message, delivered_at
		 FROM webhook_deliveries
		 WHERE repository_id = $1
		 ORDER BY delivered_at DESC
		 LIMIT $2`,
		repoID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanDeliveries(rows)
}

// GetRecentDeliveries retrieves the most recent deliveries across all repositories
func (s *WebhookDeliveryStore) GetRecentDeliveries(ctx context.Context, limit int) ([]*handlers.WebhookDelivery, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	rows, err := s.pool.Query(ctx,
		`SELECT id, repository_id, event_type, payload, response_code, response_body,
		        success, error_message, delivered_at
		 FROM webhook_deliveries
		 ORDER BY delivered_at DESC
		 LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanDeliveries(rows)
}

// DeleteOldDeliveries removes deliveries older than the specified duration
func (s *WebhookDeliveryStore) DeleteOldDeliveries(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)

	result, err := s.pool.Exec(ctx,
		`DELETE FROM webhook_deliveries WHERE delivered_at < $1`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected(), nil
}

// scanDeliveries is a helper to scan rows into WebhookDelivery slices
func scanDeliveries(rows pgx.Rows) ([]*handlers.WebhookDelivery, error) {
	var deliveries []*handlers.WebhookDelivery

	for rows.Next() {
		var delivery handlers.WebhookDelivery
		err := rows.Scan(
			&delivery.ID,
			&delivery.RepositoryID,
			&delivery.EventType,
			&delivery.Payload,
			&delivery.ResponseCode,
			&delivery.ResponseBody,
			&delivery.Success,
			&delivery.ErrorMessage,
			&delivery.DeliveredAt,
		)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, &delivery)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return deliveries, nil
}
