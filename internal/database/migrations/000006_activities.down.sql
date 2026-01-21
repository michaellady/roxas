-- Drop activities table indexes and table
DROP INDEX IF EXISTS idx_activities_post_id;
DROP INDEX IF EXISTS idx_activities_draft_id;
DROP INDEX IF EXISTS idx_activities_type;
DROP INDEX IF EXISTS idx_activities_created_at;
DROP INDEX IF EXISTS idx_activities_user_id;
DROP TABLE IF EXISTS activities;
