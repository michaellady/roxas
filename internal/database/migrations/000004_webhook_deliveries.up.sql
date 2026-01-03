-- Webhook deliveries table to track webhook events
CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,       -- e.g., "push", "pull_request"
    payload JSONB NOT NULL,                 -- Raw webhook payload
    status_code INTEGER NOT NULL,           -- HTTP response status code (200=success, 4xx/5xx=failure)
    error_message TEXT,                     -- Error message if failed
    processed_at TIMESTAMP,                 -- When processing completed
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes for efficient queries
CREATE INDEX idx_webhook_deliveries_repository_id ON webhook_deliveries(repository_id);
CREATE INDEX idx_webhook_deliveries_created_at ON webhook_deliveries(created_at DESC);
CREATE INDEX idx_webhook_deliveries_status_code ON webhook_deliveries(status_code);
