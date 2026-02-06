-- Link repositories table to GitHub App model for gradual migration
-- Existing repos keep webhook_source = 'legacy'

ALTER TABLE repositories ADD COLUMN github_app_repo_id UUID REFERENCES github_app_repositories(id);
ALTER TABLE repositories ADD COLUMN webhook_source VARCHAR(20) NOT NULL DEFAULT 'legacy';
-- 'legacy' = per-repo webhook, 'github_app' = via GitHub App
