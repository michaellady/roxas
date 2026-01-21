-- Add GitHub-specific metadata to repositories table for OAuth flow
-- Required for auto-installing webhooks via GitHub API

ALTER TABLE repositories
    ADD COLUMN github_repo_id BIGINT,
    ADD COLUMN webhook_id BIGINT,
    ADD COLUMN is_private BOOLEAN DEFAULT FALSE;

-- Index for looking up by GitHub repo ID (for webhook verification)
CREATE INDEX idx_repositories_github_repo_id ON repositories(github_repo_id);

-- Index for looking up by webhook ID (for cleanup operations)
CREATE INDEX idx_repositories_webhook_id ON repositories(webhook_id);
