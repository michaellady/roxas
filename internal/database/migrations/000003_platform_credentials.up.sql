-- Platform credentials table for OAuth token storage
-- Stores encrypted access/refresh tokens per user per platform

CREATE TABLE platform_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    platform VARCHAR(50) NOT NULL CHECK (platform IN (
        'linkedin', 'twitter', 'instagram', 'youtube',
        'bluesky', 'threads', 'tiktok'
    )),
    access_token TEXT NOT NULL,           -- Encrypted at application layer
    refresh_token TEXT,                    -- Encrypted at application layer, nullable
    token_expires_at TIMESTAMP,            -- NULL if token doesn't expire
    platform_user_id VARCHAR(255),         -- Platform-specific user identifier
    scopes TEXT,                           -- Comma-separated list of granted scopes
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_user_platform UNIQUE(user_id, platform)
);

-- Index for looking up credentials by user
CREATE INDEX idx_platform_credentials_user_id ON platform_credentials(user_id);

-- Index for finding expiring tokens (for background refresh jobs)
CREATE INDEX idx_platform_credentials_expires_at ON platform_credentials(token_expires_at)
    WHERE token_expires_at IS NOT NULL;

-- Trigger to auto-update updated_at
CREATE TRIGGER update_platform_credentials_updated_at
    BEFORE UPDATE ON platform_credentials
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
