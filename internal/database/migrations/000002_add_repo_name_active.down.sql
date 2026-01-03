-- Remove name and is_active columns from repositories table
ALTER TABLE repositories DROP COLUMN IF EXISTS name;
ALTER TABLE repositories DROP COLUMN IF EXISTS is_active;
