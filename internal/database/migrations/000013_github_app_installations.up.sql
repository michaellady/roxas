-- GitHub App installations table
-- Tracks each GitHub App installation and maps it to a Roxas user

CREATE TABLE github_app_installations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    installation_id BIGINT NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_login VARCHAR(255) NOT NULL,
    account_id BIGINT NOT NULL,
    account_type VARCHAR(50) NOT NULL,
    suspended_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_github_app_installations_user_id ON github_app_installations(user_id);
CREATE INDEX idx_github_app_installations_account_id ON github_app_installations(account_id);

-- Auto-update updated_at
CREATE TRIGGER update_github_app_installations_updated_at
    BEFORE UPDATE ON github_app_installations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
