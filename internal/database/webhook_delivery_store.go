package database

import (
	"context"
	"encoding/json"
	"time"
)

// WebhookDelivery represents a webhook delivery event
type WebhookDelivery struct {
	ID           string          `json:"id"`
	RepositoryID string          `json:"repository_id"`
	EventType    string          `json:"event_type"`
	Payload      json.RawMessage `json:"payload"`
	StatusCode   int             `json:"status_code"`
	ErrorMessage *string         `json:"error_message,omitempty"`
	ProcessedAt  *time.Time      `json:"processed_at,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}

// IsSuccess returns true if the delivery was successful (2xx status code)
func (d *WebhookDelivery) IsSuccess() bool {
	return d.StatusCode >= 200 && d.StatusCode < 300
}

// PayloadPreview returns a truncated preview of the payload
func (d *WebhookDelivery) PayloadPreview(maxLen int) string {
	s := string(d.Payload)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// WebhookDeliveryStore handles webhook delivery persistence
type WebhookDeliveryStore struct {
	pool *Pool
}

// NewWebhookDeliveryStore creates a new webhook delivery store
func NewWebhookDeliveryStore(pool *Pool) *WebhookDeliveryStore {
	return &WebhookDeliveryStore{pool: pool}
}

// CreateDelivery records a new webhook delivery
func (s *WebhookDeliveryStore) CreateDelivery(ctx context.Context, repoID, eventType string, payload json.RawMessage, statusCode int, errorMessage *string) (*WebhookDelivery, error) {
	var delivery WebhookDelivery
	var processedAt *time.Time
	now := time.Now()
	processedAt = &now

	err := s.pool.QueryRow(ctx,
		`INSERT INTO webhook_deliveries (repository_id, event_type, payload, status_code, error_message, processed_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, repository_id, event_type, payload, status_code, error_message, processed_at, created_at`,
		repoID, eventType, payload, statusCode, errorMessage, processedAt,
	).Scan(&delivery.ID, &delivery.RepositoryID, &delivery.EventType, &delivery.Payload,
		&delivery.StatusCode, &delivery.ErrorMessage, &delivery.ProcessedAt, &delivery.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &delivery, nil
}

// ListDeliveriesByRepository retrieves recent webhook deliveries for a repository
func (s *WebhookDeliveryStore) ListDeliveriesByRepository(ctx context.Context, repoID string, limit int) ([]*WebhookDelivery, error) {
	if limit <= 0 {
		limit = 20 // Default limit
	}

	rows, err := s.pool.Query(ctx,
		`SELECT id, repository_id, event_type, payload, status_code, error_message, processed_at, created_at
		 FROM webhook_deliveries
		 WHERE repository_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`,
		repoID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []*WebhookDelivery
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(&d.ID, &d.RepositoryID, &d.EventType, &d.Payload,
			&d.StatusCode, &d.ErrorMessage, &d.ProcessedAt, &d.CreatedAt); err != nil {
			return nil, err
		}
		deliveries = append(deliveries, &d)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return deliveries, nil
}

// GetDeliveryByID retrieves a single delivery by ID
func (s *WebhookDeliveryStore) GetDeliveryByID(ctx context.Context, deliveryID string) (*WebhookDelivery, error) {
	var d WebhookDelivery

	err := s.pool.QueryRow(ctx,
		`SELECT id, repository_id, event_type, payload, status_code, error_message, processed_at, created_at
		 FROM webhook_deliveries
		 WHERE id = $1`,
		deliveryID,
	).Scan(&d.ID, &d.RepositoryID, &d.EventType, &d.Payload,
		&d.StatusCode, &d.ErrorMessage, &d.ProcessedAt, &d.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &d, nil
}
