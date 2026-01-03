package handlers

import (
	"context"
	"time"
)

// =============================================================================
// WebhookDelivery Model and Store Interface (hq-cgm.3)
// Tracks webhook delivery attempts for debugging and UI display
// =============================================================================

// WebhookDelivery represents a single webhook delivery attempt
type WebhookDelivery struct {
	ID           string    `json:"id"`
	RepositoryID string    `json:"repository_id"`
	EventType    string    `json:"event_type"`    // e.g., "push", "ping", "pull_request"
	Payload      string    `json:"payload"`       // Raw JSON payload (may be truncated for storage)
	ResponseCode int       `json:"response_code"` // HTTP response code we returned
	ResponseBody string    `json:"response_body"` // Response we sent back
	Success      bool      `json:"success"`       // True if we processed successfully
	ErrorMessage string    `json:"error_message,omitempty"` // Error details if failed
	DeliveredAt  time.Time `json:"delivered_at"`
}

// WebhookDeliveryStore defines the interface for webhook delivery persistence
type WebhookDeliveryStore interface {
	// RecordDelivery stores a webhook delivery attempt
	RecordDelivery(ctx context.Context, delivery *WebhookDelivery) error

	// GetDelivery retrieves a specific delivery by ID
	GetDelivery(ctx context.Context, deliveryID string) (*WebhookDelivery, error)

	// ListDeliveriesForRepository retrieves recent deliveries for a repository
	// Returns deliveries ordered by delivered_at DESC, limited to the specified count
	ListDeliveriesForRepository(ctx context.Context, repoID string, limit int) ([]*WebhookDelivery, error)

	// GetRecentDeliveries retrieves the most recent deliveries across all repositories
	// Useful for admin/debugging views
	GetRecentDeliveries(ctx context.Context, limit int) ([]*WebhookDelivery, error)

	// DeleteOldDeliveries removes deliveries older than the specified duration
	// Used for cleanup to prevent unbounded table growth
	DeleteOldDeliveries(ctx context.Context, olderThan time.Duration) (int64, error)
}

// NewWebhookDelivery creates a new WebhookDelivery with the current timestamp
func NewWebhookDelivery(repoID, eventType, payload string, responseCode int, responseBody string, success bool) *WebhookDelivery {
	return &WebhookDelivery{
		RepositoryID: repoID,
		EventType:    eventType,
		Payload:      payload,
		ResponseCode: responseCode,
		ResponseBody: responseBody,
		Success:      success,
		DeliveredAt:  time.Now(),
	}
}

// NewFailedDelivery creates a WebhookDelivery for a failed delivery attempt
func NewFailedDelivery(repoID, eventType, payload string, responseCode int, errorMessage string) *WebhookDelivery {
	return &WebhookDelivery{
		RepositoryID: repoID,
		EventType:    eventType,
		Payload:      payload,
		ResponseCode: responseCode,
		ResponseBody: errorMessage,
		Success:      false,
		ErrorMessage: errorMessage,
		DeliveredAt:  time.Now(),
	}
}

// MaxPayloadSize is the maximum payload size to store (to prevent huge payloads)
const MaxPayloadSize = 65536 // 64KB

// TruncatePayload truncates a payload to MaxPayloadSize if needed
func TruncatePayload(payload string) string {
	if len(payload) > MaxPayloadSize {
		return payload[:MaxPayloadSize] + "...[truncated]"
	}
	return payload
}
