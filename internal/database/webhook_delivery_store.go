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
	DeliveryID   string          `json:"delivery_id"` // X-GitHub-Delivery header for idempotency
	EventType    string          `json:"event_type"`
	Ref          *string         `json:"ref,omitempty"`        // Git ref (branch) for push events
	BeforeSHA    *string         `json:"before_sha,omitempty"` // Commit SHA before push
	AfterSHA     *string         `json:"after_sha,omitempty"`  // Commit SHA after push
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
	db DBTX
}

// NewWebhookDeliveryStore creates a new webhook delivery store
func NewWebhookDeliveryStore(pool *Pool) *WebhookDeliveryStore {
	return &WebhookDeliveryStore{db: pool}
}

// NewWebhookDeliveryStoreWithDB creates a webhook delivery store with a custom DBTX implementation.
// This is primarily used for testing with pgxmock.
func NewWebhookDeliveryStoreWithDB(db DBTX) *WebhookDeliveryStore {
	return &WebhookDeliveryStore{db: db}
}

// CreateDeliveryParams holds parameters for creating a webhook delivery
type CreateDeliveryParams struct {
	RepositoryID string
	DeliveryID   string // X-GitHub-Delivery header
	EventType    string
	Ref          *string // Git ref for push events
	BeforeSHA    *string // Commit SHA before push
	AfterSHA     *string // Commit SHA after push
	Payload      json.RawMessage
	StatusCode   int
	ErrorMessage *string
}

// CreateDeliveryLegacy records a new webhook delivery using legacy parameters
func (s *WebhookDeliveryStore) CreateDeliveryLegacy(ctx context.Context, repoID, eventType string, payload json.RawMessage, statusCode int, errorMessage *string) (*WebhookDelivery, error) {
	// Legacy method - generates a unique delivery_id
	return s.CreateDelivery(ctx, CreateDeliveryParams{
		RepositoryID: repoID,
		DeliveryID:   "", // Will be set to UUID by the query
		EventType:    eventType,
		Payload:      payload,
		StatusCode:   statusCode,
		ErrorMessage: errorMessage,
	})
}

// CreateDelivery records a new webhook delivery with full parameters including idempotency fields
func (s *WebhookDeliveryStore) CreateDelivery(ctx context.Context, params CreateDeliveryParams) (*WebhookDelivery, error) {
	var delivery WebhookDelivery
	now := time.Now()

	// If no delivery_id provided, generate one from UUID
	deliveryID := params.DeliveryID
	if deliveryID == "" {
		deliveryID = "generated-" + now.Format("20060102150405.000000")
	}

	err := s.db.QueryRow(ctx,
		`INSERT INTO webhook_deliveries (repository_id, delivery_id, event_type, ref, before_sha, after_sha, payload, status_code, error_message, processed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id, repository_id, delivery_id, event_type, ref, before_sha, after_sha, payload, status_code, error_message, processed_at, created_at`,
		params.RepositoryID, deliveryID, params.EventType, params.Ref, params.BeforeSHA, params.AfterSHA, params.Payload, params.StatusCode, params.ErrorMessage, &now,
	).Scan(&delivery.ID, &delivery.RepositoryID, &delivery.DeliveryID, &delivery.EventType,
		&delivery.Ref, &delivery.BeforeSHA, &delivery.AfterSHA, &delivery.Payload,
		&delivery.StatusCode, &delivery.ErrorMessage, &delivery.ProcessedAt, &delivery.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &delivery, nil
}

// ExistsByDeliveryID checks if a delivery with the given delivery_id already exists for a repository
func (s *WebhookDeliveryStore) ExistsByDeliveryID(ctx context.Context, repoID, deliveryID string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM webhook_deliveries WHERE repository_id = $1 AND delivery_id = $2)`,
		repoID, deliveryID,
	).Scan(&exists)
	return exists, err
}

// DeliveryExists checks if a delivery with the given delivery_id already exists (global lookup)
func (s *WebhookDeliveryStore) DeliveryExists(ctx context.Context, deliveryID string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx,
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

	rows, err := s.db.Query(ctx,
		`SELECT id, repository_id, delivery_id, event_type, ref, before_sha, after_sha, payload, status_code, error_message, processed_at, created_at
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
		if err := rows.Scan(&d.ID, &d.RepositoryID, &d.DeliveryID, &d.EventType,
			&d.Ref, &d.BeforeSHA, &d.AfterSHA, &d.Payload,
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
func (s *WebhookDeliveryStore) GetDeliveryByID(ctx context.Context, id string) (*WebhookDelivery, error) {
	var d WebhookDelivery

	err := s.db.QueryRow(ctx,
		`SELECT id, repository_id, delivery_id, event_type, ref, before_sha, after_sha, payload, status_code, error_message, processed_at, created_at
		 FROM webhook_deliveries
		 WHERE id = $1`,
		id,
	).Scan(&d.ID, &d.RepositoryID, &d.DeliveryID, &d.EventType,
		&d.Ref, &d.BeforeSHA, &d.AfterSHA, &d.Payload,
		&d.StatusCode, &d.ErrorMessage, &d.ProcessedAt, &d.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &d, nil
}

// =============================================================================
// IdempotencyStore interface methods (for DraftCreatingWebhookHandler)
// =============================================================================

// CheckDeliveryProcessed checks if a delivery with the given ID has already been processed.
// This implements the IdempotencyStore interface for webhook deduplication.
func (s *WebhookDeliveryStore) CheckDeliveryProcessed(ctx context.Context, deliveryID string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM webhook_deliveries WHERE delivery_id = $1)`,
		deliveryID,
	).Scan(&exists)
	return exists, err
}

// MarkDeliveryProcessed records that a delivery has been processed.
// This implements the IdempotencyStore interface for webhook deduplication.
// It creates a minimal delivery record to mark the delivery_id as processed.
func (s *WebhookDeliveryStore) MarkDeliveryProcessed(ctx context.Context, deliveryID, repoID string) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO webhook_deliveries (repository_id, delivery_id, event_type, payload, status_code, processed_at)
		 VALUES ($1, $2, 'push', '{}', 200, NOW())
		 ON CONFLICT (delivery_id) DO NOTHING`,
		repoID, deliveryID,
	)
	return err
}
