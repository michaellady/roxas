-- Remove GitHub-specific metadata from repositories table

DROP INDEX IF EXISTS idx_repositories_webhook_id;
DROP INDEX IF EXISTS idx_repositories_github_repo_id;

ALTER TABLE repositories
    DROP COLUMN IF EXISTS is_private,
    DROP COLUMN IF EXISTS webhook_id,
    DROP COLUMN IF EXISTS github_repo_id;
