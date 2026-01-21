-- Add drafts table for storing push-generated social media drafts
-- Each draft represents a single push event (may contain multiple commits)

CREATE TABLE drafts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ref VARCHAR(255) NOT NULL,                    -- e.g., 'refs/heads/main'
    before_sha VARCHAR(40),                       -- Push before SHA (NULL for new branches)
    after_sha VARCHAR(40) NOT NULL,               -- Push after SHA (head of push)
    commit_shas JSONB NOT NULL,                   -- Array of commit SHAs in the push
    commit_count INT NOT NULL DEFAULT 1,          -- Number of commits in push
    generated_content TEXT,                       -- AI-generated post content (NULL if generation failed)
    generated_image_url VARCHAR(512),             -- Post-MVP: S3 URL for AI-generated image
    edited_content TEXT,                          -- User's edited version (NULL if not edited)
    status VARCHAR(20) NOT NULL DEFAULT 'draft'   -- draft, posted, partial, failed, error
        CHECK (status IN ('draft', 'posted', 'partial', 'failed', 'error')),
    error_message TEXT,                           -- Error details if status is 'error' or 'failed'
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    posted_at TIMESTAMP,                          -- When draft was first successfully posted
    CONSTRAINT unique_user_push UNIQUE(user_id, repository_id, ref, after_sha)
);

-- Index for drafts page (pending drafts by user, filtered by status)
CREATE INDEX idx_drafts_user_status ON drafts(user_id, status);

-- Index for drafts sorted by creation time (activity feed, newest first)
CREATE INDEX idx_drafts_user_created ON drafts(user_id, created_at DESC);

-- Index for looking up drafts by repository
CREATE INDEX idx_drafts_repository ON drafts(repository_id);

-- Trigger to auto-update updated_at (reuses function from initial schema)
CREATE TRIGGER update_drafts_updated_at BEFORE UPDATE ON drafts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
