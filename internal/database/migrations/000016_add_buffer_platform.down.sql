-- Remove 'buffer' from the platform_credentials CHECK constraint
-- First delete any buffer credentials, then restore original constraint

DELETE FROM platform_credentials WHERE platform = 'buffer';

ALTER TABLE platform_credentials
    DROP CONSTRAINT IF EXISTS platform_credentials_platform_check;

ALTER TABLE platform_credentials
    ADD CONSTRAINT platform_credentials_platform_check
    CHECK (platform IN (
        'linkedin', 'twitter', 'instagram', 'youtube',
        'bluesky', 'threads', 'tiktok'
    ));
