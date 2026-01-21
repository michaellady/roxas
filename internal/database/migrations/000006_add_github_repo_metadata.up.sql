-- Add GitHub API metadata columns to repositories table
-- github_repo_id: GitHub's numeric repo ID from API
-- webhook_id: GitHub's webhook ID for management
-- is_private: Whether the repository is private

ALTER TABLE repositories ADD COLUMN github_repo_id BIGINT;
ALTER TABLE repositories ADD COLUMN webhook_id BIGINT;
ALTER TABLE repositories ADD COLUMN is_private BOOLEAN NOT NULL DEFAULT false;

-- Index for looking up repos by GitHub ID
CREATE INDEX idx_repositories_github_repo_id ON repositories(github_repo_id);
