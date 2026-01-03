-- Add health check columns to platform_credentials
-- Tracks connection health status for background monitoring

ALTER TABLE platform_credentials
    ADD COLUMN last_health_check TIMESTAMP,
    ADD COLUMN is_healthy BOOLEAN DEFAULT true,
    ADD COLUMN health_error TEXT,
    ADD COLUMN last_successful_post TIMESTAMP;

-- Index for finding unhealthy connections
CREATE INDEX idx_platform_credentials_health ON platform_credentials(is_healthy)
    WHERE is_healthy = false;

-- Index for finding connections that need health check
CREATE INDEX idx_platform_credentials_last_check ON platform_credentials(last_health_check)
    WHERE last_health_check IS NOT NULL;
