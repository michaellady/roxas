-- Initial schema for multi-tenant SaaS platform
-- Users → Repositories → Commits → Posts

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table (root of multi-tenancy)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index for email lookups (login)
CREATE INDEX idx_users_email ON users(email);

-- Repositories table (GitHub repos tracked per user)
CREATE TABLE repositories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    github_url VARCHAR(512) NOT NULL,
    webhook_secret VARCHAR(255) NOT NULL UNIQUE,
    last_synced_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_user_repo UNIQUE(user_id, github_url)
);

-- Indexes for repository queries
CREATE INDEX idx_repositories_user_id ON repositories(user_id);
CREATE INDEX idx_repositories_webhook_secret ON repositories(webhook_secret);

-- Commits table (lightweight metadata, GitHub is source of truth)
CREATE TABLE commits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    commit_sha VARCHAR(40) NOT NULL,
    github_url VARCHAR(512) NOT NULL,
    commit_message TEXT,
    author VARCHAR(255),
    timestamp TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_repo_commit UNIQUE(repository_id, commit_sha)
);

-- Indexes for commit queries
CREATE INDEX idx_commits_repository_id ON commits(repository_id);
CREATE INDEX idx_commits_sha ON commits(repository_id, commit_sha);
CREATE INDEX idx_commits_timestamp ON commits(timestamp DESC);

-- Posts table (generated social media content)
CREATE TABLE posts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    commit_id UUID NOT NULL REFERENCES commits(id) ON DELETE CASCADE,
    platform VARCHAR(50) NOT NULL CHECK (platform IN ('linkedin', 'youtube', 'instagram', 'tiktok', 'twitter')),
    content TEXT NOT NULL,
    media_url VARCHAR(512),
    status VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'posted', 'failed')),
    posted_at TIMESTAMP,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_commit_platform_version UNIQUE(commit_id, platform, version)
);

-- Indexes for post queries
CREATE INDEX idx_posts_commit_id ON posts(commit_id);
CREATE INDEX idx_posts_platform ON posts(platform);
CREATE INDEX idx_posts_status ON posts(status);
CREATE INDEX idx_posts_created_at ON posts(created_at DESC);

-- Updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to auto-update updated_at on users table
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
