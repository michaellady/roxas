-- Webhook deliveries table for tracking webhook delivery attempts
-- Used for debugging, UI display, and test webhook functionality

CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,          -- e.g., 'push', 'ping', 'pull_request'
    payload TEXT NOT NULL,                     -- Raw JSON payload (truncated if too large)
    response_code INTEGER NOT NULL,            -- HTTP response code returned
    response_body TEXT,                        -- Response body sent back
    success BOOLEAN NOT NULL DEFAULT false,    -- Whether processing succeeded
    error_message TEXT,                        -- Error details if failed
    delivered_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index for listing deliveries by repository (most common query)
CREATE INDEX idx_webhook_deliveries_repository_id ON webhook_deliveries(repository_id);

-- Index for finding recent deliveries (for UI and cleanup)
CREATE INDEX idx_webhook_deliveries_delivered_at ON webhook_deliveries(delivered_at DESC);

-- Composite index for repository + time queries
CREATE INDEX idx_webhook_deliveries_repo_delivered ON webhook_deliveries(repository_id, delivered_at DESC);
