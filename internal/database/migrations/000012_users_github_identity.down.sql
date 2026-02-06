-- Revert GitHub identity fields from users table
ALTER TABLE users DROP COLUMN IF EXISTS github_login;
ALTER TABLE users DROP COLUMN IF EXISTS github_id;
ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL;
