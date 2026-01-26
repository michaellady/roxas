-- No-op migration: webhook idempotency columns already added in migration 000009
-- This migration exists to maintain compatibility with previously deployed environments
-- where the duplicate migration was applied before being removed from the codebase.
SELECT 1;
