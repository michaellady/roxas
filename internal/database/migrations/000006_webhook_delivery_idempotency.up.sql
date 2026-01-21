-- Add columns for webhook delivery idempotency (alice-77)
-- delivery_id: X-GitHub-Delivery header for idempotency check
-- ref: git reference (branch) from push event
-- before_sha: commit SHA before push
-- after_sha: commit SHA after push

-- Add delivery_id column with default for existing rows
ALTER TABLE webhook_deliveries
    ADD COLUMN delivery_id VARCHAR(255) NOT NULL DEFAULT '';

-- Add ref, before_sha, after_sha columns (nullable - only set for push events)
ALTER TABLE webhook_deliveries
    ADD COLUMN ref VARCHAR(255),
    ADD COLUMN before_sha VARCHAR(40),
    ADD COLUMN after_sha VARCHAR(40);

-- Backfill existing rows with unique delivery_id based on their id
UPDATE webhook_deliveries SET delivery_id = id::text WHERE delivery_id = '';

-- Remove the default constraint now that existing rows are backfilled
ALTER TABLE webhook_deliveries ALTER COLUMN delivery_id DROP DEFAULT;

-- Add unique index for idempotency lookup (repo + delivery_id)
CREATE UNIQUE INDEX idx_webhook_deliveries_idempotency
    ON webhook_deliveries(repository_id, delivery_id);

-- Add index on ref for querying by branch
CREATE INDEX idx_webhook_deliveries_ref ON webhook_deliveries(ref);
