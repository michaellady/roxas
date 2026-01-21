-- Revert posts table changes (alice-79)

-- Drop new index
DROP INDEX IF EXISTS idx_posts_draft;

-- Drop foreign key to drafts
ALTER TABLE posts DROP CONSTRAINT IF EXISTS posts_draft_id_fkey;

-- Restore commit_id NOT NULL constraint
-- Note: This may fail if there are posts without commit_id
ALTER TABLE posts ALTER COLUMN commit_id SET NOT NULL;

-- Drop new columns
ALTER TABLE posts
    DROP COLUMN IF EXISTS draft_id,
    DROP COLUMN IF EXISTS platform_post_id,
    DROP COLUMN IF EXISTS platform_post_url,
    DROP COLUMN IF EXISTS error_message;

-- Restore removed columns
ALTER TABLE posts
    ADD COLUMN media_url VARCHAR(512),
    ADD COLUMN version INTEGER NOT NULL DEFAULT 1;

-- Restore original constraint
ALTER TABLE posts DROP CONSTRAINT IF EXISTS posts_status_check;
ALTER TABLE posts ADD CONSTRAINT posts_status_check
    CHECK (status IN ('draft', 'posted', 'failed'));

-- Restore original unique constraint
ALTER TABLE posts ADD CONSTRAINT unique_commit_platform_version
    UNIQUE(commit_id, platform, version);

-- Restore original index
CREATE INDEX idx_posts_commit_id ON posts(commit_id);
