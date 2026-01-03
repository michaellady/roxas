-- Rollback platform_credentials table

DROP TRIGGER IF EXISTS update_platform_credentials_updated_at ON platform_credentials;
DROP INDEX IF EXISTS idx_platform_credentials_expires_at;
DROP INDEX IF EXISTS idx_platform_credentials_user_id;
DROP TABLE IF EXISTS platform_credentials CASCADE;
