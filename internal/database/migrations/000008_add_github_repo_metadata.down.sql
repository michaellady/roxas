-- Revert GitHub API metadata columns from repositories table

DROP INDEX IF EXISTS idx_repositories_github_repo_id;

ALTER TABLE repositories DROP COLUMN IF EXISTS is_private;
ALTER TABLE repositories DROP COLUMN IF EXISTS webhook_id;
ALTER TABLE repositories DROP COLUMN IF EXISTS github_repo_id;
