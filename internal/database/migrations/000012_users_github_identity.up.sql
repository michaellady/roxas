-- Add GitHub identity fields to users table for GitHub App integration
-- password_hash becomes nullable for GitHub-only accounts (no password)

ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ADD COLUMN github_id BIGINT UNIQUE;
ALTER TABLE users ADD COLUMN github_login VARCHAR(255);
