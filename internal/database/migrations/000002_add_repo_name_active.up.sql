-- Add name and is_active columns to repositories table
-- Name: optional friendly name for the repository
-- is_active: whether the repository is actively processing webhooks

ALTER TABLE repositories ADD COLUMN name VARCHAR(255);
ALTER TABLE repositories ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT true;

-- Set default name from github_url (extract repo name from URL)
UPDATE repositories
SET name = split_part(split_part(github_url, '/', -1), '.git', 1)
WHERE name IS NULL;
