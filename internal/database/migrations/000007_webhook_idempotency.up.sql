-- Add idempotency columns to webhook_deliveries
-- delivery_id: X-GitHub-Delivery header for deduplication
-- ref, before_sha, after_sha: Push event details for additional context

-- Add delivery_id column (required for idempotency)
-- First add as nullable, backfill existing rows, then make NOT NULL
ALTER TABLE webhook_deliveries ADD COLUMN delivery_id VARCHAR(255);

-- Backfill existing rows with generated UUID to allow NOT NULL constraint
UPDATE webhook_deliveries SET delivery_id = 'legacy-' || id::text WHERE delivery_id IS NULL;

-- Now make it NOT NULL
ALTER TABLE webhook_deliveries ALTER COLUMN delivery_id SET NOT NULL;

-- Add unique index for idempotency checks
CREATE UNIQUE INDEX idx_webhook_deliveries_delivery_id ON webhook_deliveries(delivery_id);

-- Add push event context columns (nullable since not all events are push events)
ALTER TABLE webhook_deliveries ADD COLUMN ref VARCHAR(255);
ALTER TABLE webhook_deliveries ADD COLUMN before_sha VARCHAR(40);
ALTER TABLE webhook_deliveries ADD COLUMN after_sha VARCHAR(40);

-- Index on ref for filtering by branch
CREATE INDEX idx_webhook_deliveries_ref ON webhook_deliveries(ref) WHERE ref IS NOT NULL;
