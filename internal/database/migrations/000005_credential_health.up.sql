-- Add health check columns to platform_credentials
-- For tracking connection health status and last successful activity

ALTER TABLE platform_credentials
    ADD COLUMN last_health_check TIMESTAMP,
    ADD COLUMN is_healthy BOOLEAN DEFAULT TRUE,
    ADD COLUMN health_error TEXT,
    ADD COLUMN last_successful_post TIMESTAMP;

-- Index for finding credentials that need health checks
-- Query should filter by time, not the index (NOW() is volatile, can't be used in partial indexes)
CREATE INDEX idx_platform_credentials_health_check
    ON platform_credentials(last_health_check)
    WHERE is_healthy = FALSE;
