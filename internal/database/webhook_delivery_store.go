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
	DeliveryID   string          `json:"delivery_id"`
	EventType    string          `json:"event_type"`
	Payload      json.RawMessage `json:"payload"`
	StatusCode   int             `json:"status_code"`
	ErrorMessage *string         `json:"error_message,omitempty"`
	ProcessedAt  *time.Time      `json:"processed_at,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	Ref          *string         `json:"ref,omitempty"`
	BeforeSHA    *string         `json:"before_sha,omitempty"`
	AfterSHA     *string         `json:"after_sha,omitempty"`
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

// CreateDeliveryParams contains parameters for creating a webhook delivery
type CreateDeliveryParams struct {
	RepositoryID string
	DeliveryID   string
	EventType    string
	Payload      json.RawMessage
	StatusCode   int
	ErrorMessage *string
	Ref          *string
	BeforeSHA    *string
	AfterSHA     *string
}

// CreateDelivery records a new webhook delivery
func (s *WebhookDeliveryStore) CreateDelivery(ctx context.Context, params CreateDeliveryParams) (*WebhookDelivery, error) {
	var delivery WebhookDelivery
	now := time.Now()

	err := s.pool.QueryRow(ctx,
		`INSERT INTO webhook_deliveries (repository_id, delivery_id, event_type, payload, status_code, error_message, processed_at, ref, before_sha, after_sha)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id, repository_id, delivery_id, event_type, payload, status_code, error_message, processed_at, created_at, ref, before_sha, after_sha`,
		params.RepositoryID, params.DeliveryID, params.EventType, params.Payload, params.StatusCode, params.ErrorMessage, &now, params.Ref, params.BeforeSHA, params.AfterSHA,
	).Scan(&delivery.ID, &delivery.RepositoryID, &delivery.DeliveryID, &delivery.EventType, &delivery.Payload,
		&delivery.StatusCode, &delivery.ErrorMessage, &delivery.ProcessedAt, &delivery.CreatedAt,
		&delivery.Ref, &delivery.BeforeSHA, &delivery.AfterSHA)

	if err != nil {
		return nil, err
	}

	return &delivery, nil
}

// DeliveryExists checks if a delivery with the given delivery_id already exists
func (s *WebhookDeliveryStore) DeliveryExists(ctx context.Context, deliveryID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM webhook_deliveries WHERE delivery_id = $1)`,
		deliveryID,
	).Scan(&exists)
	return exists, err
}

// ListDeliveriesByRepository retrieves recent webhook deliveries for a repository
func (s *WebhookDeliveryStore) ListDeliveriesByRepository(ctx context.Context, repoID string, limit int) ([]*WebhookDelivery, error) {
	if limit <= 0 {
		limit = 20 // Default limit
	}

	rows, err := s.pool.Query(ctx,
		`SELECT id, repository_id, delivery_id, event_type, payload, status_code, error_message, processed_at, created_at, ref, before_sha, after_sha
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
		if err := rows.Scan(&d.ID, &d.RepositoryID, &d.DeliveryID, &d.EventType, &d.Payload,
			&d.StatusCode, &d.ErrorMessage, &d.ProcessedAt, &d.CreatedAt,
			&d.Ref, &d.BeforeSHA, &d.AfterSHA); err != nil {
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
func (s *WebhookDeliveryStore) GetDeliveryByID(ctx context.Context, id string) (*WebhookDelivery, error) {
	var d WebhookDelivery

	err := s.pool.QueryRow(ctx,
		`SELECT id, repository_id, delivery_id, event_type, payload, status_code, error_message, processed_at, created_at, ref, before_sha, after_sha
		 FROM webhook_deliveries
		 WHERE id = $1`,
		id,
	).Scan(&d.ID, &d.RepositoryID, &d.DeliveryID, &d.EventType, &d.Payload,
		&d.StatusCode, &d.ErrorMessage, &d.ProcessedAt, &d.CreatedAt,
		&d.Ref, &d.BeforeSHA, &d.AfterSHA)

	if err != nil {
		return nil, err
	}

	return &d, nil
}
