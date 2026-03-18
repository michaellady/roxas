-- Add 'buffer' to the platform_credentials CHECK constraint
-- Drop the existing constraint and recreate it with 'buffer' included

ALTER TABLE platform_credentials
    DROP CONSTRAINT IF EXISTS platform_credentials_platform_check;

ALTER TABLE platform_credentials
    ADD CONSTRAINT platform_credentials_platform_check
    CHECK (platform IN (
        'linkedin', 'twitter', 'instagram', 'youtube',
        'bluesky', 'threads', 'tiktok', 'buffer'
    ));
