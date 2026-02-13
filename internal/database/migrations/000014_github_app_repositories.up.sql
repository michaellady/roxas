-- GitHub App repositories table
-- Repos synced from installation events, linked to existing repositories table

CREATE TABLE github_app_repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    installation_id BIGINT NOT NULL REFERENCES github_app_installations(installation_id) ON DELETE CASCADE,
    github_repo_id BIGINT NOT NULL,
    full_name VARCHAR(512) NOT NULL,
    html_url VARCHAR(512) NOT NULL,
    private BOOLEAN NOT NULL DEFAULT false,
    default_branch VARCHAR(255) DEFAULT 'main',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(installation_id, github_repo_id)
);

CREATE INDEX idx_github_app_repositories_installation_id ON github_app_repositories(installation_id);
CREATE INDEX idx_github_app_repositories_github_repo_id ON github_app_repositories(github_repo_id);

-- Auto-update updated_at
CREATE TRIGGER update_github_app_repositories_updated_at
    BEFORE UPDATE ON github_app_repositories
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
