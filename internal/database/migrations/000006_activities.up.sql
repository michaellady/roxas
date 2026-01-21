-- Activities table to track user actions (draft creation, post success/failure)
CREATE TABLE activities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL CHECK (type IN ('draft_created', 'post_success', 'post_failed')),
    draft_id UUID,                              -- References draft (no FK until drafts table exists)
    post_id UUID REFERENCES posts(id) ON DELETE SET NULL,
    platform VARCHAR(50),                       -- e.g., 'threads', 'linkedin', etc.
    message TEXT,                               -- Activity description or error message
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes for efficient queries
CREATE INDEX idx_activities_user_id ON activities(user_id);
CREATE INDEX idx_activities_created_at ON activities(created_at DESC);
CREATE INDEX idx_activities_type ON activities(type);
CREATE INDEX idx_activities_draft_id ON activities(draft_id);
CREATE INDEX idx_activities_post_id ON activities(post_id);
