-- Add health check columns to platform_credentials
-- For tracking connection health status and last successful activity

ALTER TABLE platform_credentials
    ADD COLUMN last_health_check TIMESTAMP,
    ADD COLUMN is_healthy BOOLEAN DEFAULT TRUE,
    ADD COLUMN health_error TEXT,
    ADD COLUMN last_successful_post TIMESTAMP;

-- Index for finding credentials that need health checks
-- (not checked recently or not healthy)
CREATE INDEX idx_platform_credentials_health_check
    ON platform_credentials(last_health_check)
    WHERE last_health_check IS NULL OR last_health_check < NOW() - INTERVAL '24 hours';
