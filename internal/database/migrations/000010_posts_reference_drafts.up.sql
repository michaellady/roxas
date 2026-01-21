-- Update posts table to reference drafts instead of commits (alice-79)
-- Posts are now created from drafts, not directly from commits

-- Drop existing indexes and constraints that reference commit_id
DROP INDEX IF EXISTS idx_posts_commit_id;
ALTER TABLE posts DROP CONSTRAINT IF EXISTS unique_commit_platform_version;

-- Add new columns
ALTER TABLE posts
    ADD COLUMN draft_id UUID,
    ADD COLUMN platform_post_id VARCHAR(255),
    ADD COLUMN platform_post_url VARCHAR(512),
    ADD COLUMN error_message TEXT;

-- For existing posts, we need to handle the migration
-- Since draft_id references drafts which references commits, we can't directly map
-- For now, we'll make draft_id nullable initially for existing data
-- New posts will require draft_id

-- Remove columns no longer in spec
ALTER TABLE posts DROP COLUMN IF EXISTS media_url;
ALTER TABLE posts DROP COLUMN IF EXISTS version;

-- Update status constraint - posts now only have 'posted' or 'failed' status
-- Draft status is now on the drafts table
-- First drop the old constraint
ALTER TABLE posts DROP CONSTRAINT IF EXISTS posts_status_check;

-- Add the new constraint (allowing existing 'draft' values during transition)
ALTER TABLE posts ADD CONSTRAINT posts_status_check
    CHECK (status IN ('draft', 'posted', 'failed'));

-- Now we can drop commit_id after adding draft_id
-- For migration, we'll keep commit_id temporarily as nullable
ALTER TABLE posts ALTER COLUMN commit_id DROP NOT NULL;

-- Add foreign key constraint for draft_id (nullable for existing data)
ALTER TABLE posts ADD CONSTRAINT posts_draft_id_fkey
    FOREIGN KEY (draft_id) REFERENCES drafts(id) ON DELETE CASCADE;

-- Create new index for draft lookups
CREATE INDEX idx_posts_draft ON posts(draft_id);

-- Note: commit_id column is kept for backwards compatibility during migration
-- A future migration can remove it once all posts reference drafts
