-- Remove drafts table and associated objects

DROP TRIGGER IF EXISTS update_drafts_updated_at ON drafts;
DROP INDEX IF EXISTS idx_drafts_repository;
DROP INDEX IF EXISTS idx_drafts_user_created;
DROP INDEX IF EXISTS idx_drafts_user_status;
DROP TABLE IF EXISTS drafts;
