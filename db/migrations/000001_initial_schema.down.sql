-- Rollback initial schema
-- Drop tables in reverse order (respecting foreign key dependencies)

-- Drop trigger and function
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop tables (cascade will handle foreign keys)
DROP TABLE IF EXISTS posts CASCADE;
DROP TABLE IF EXISTS commits CASCADE;
DROP TABLE IF EXISTS repositories CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Drop UUID extension (optional, may be used by other schemas)
-- DROP EXTENSION IF EXISTS "uuid-ossp";
