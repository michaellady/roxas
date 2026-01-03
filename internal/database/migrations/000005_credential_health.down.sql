-- Remove health check columns from platform_credentials

DROP INDEX IF EXISTS idx_platform_credentials_health;
DROP INDEX IF EXISTS idx_platform_credentials_last_check;

ALTER TABLE platform_credentials
    DROP COLUMN IF EXISTS last_health_check,
    DROP COLUMN IF EXISTS is_healthy,
    DROP COLUMN IF EXISTS health_error,
    DROP COLUMN IF EXISTS last_successful_post;
