-- Add idempotency columns to webhook_deliveries
-- delivery_id: X-GitHub-Delivery header for deduplication
-- ref, before_sha, after_sha: Push event details for additional context

-- Add delivery_id column (required for idempotency) - idempotent
DO $$ BEGIN
    ALTER TABLE webhook_deliveries ADD COLUMN delivery_id VARCHAR(255);
EXCEPTION
    WHEN duplicate_column THEN NULL;
END $$;

-- Backfill existing rows with generated UUID to allow NOT NULL constraint
UPDATE webhook_deliveries SET delivery_id = 'legacy-' || id::text WHERE delivery_id IS NULL;

-- Now make it NOT NULL (idempotent - only if not already set)
DO $$ BEGIN
    ALTER TABLE webhook_deliveries ALTER COLUMN delivery_id SET NOT NULL;
EXCEPTION
    WHEN others THEN NULL;
END $$;

-- Add unique index for idempotency checks (idempotent)
CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_deliveries_delivery_id ON webhook_deliveries(delivery_id);

-- Add push event context columns (nullable since not all events are push events) - idempotent
DO $$ BEGIN
    ALTER TABLE webhook_deliveries ADD COLUMN ref VARCHAR(255);
EXCEPTION
    WHEN duplicate_column THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE webhook_deliveries ADD COLUMN before_sha VARCHAR(40);
EXCEPTION
    WHEN duplicate_column THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE webhook_deliveries ADD COLUMN after_sha VARCHAR(40);
EXCEPTION
    WHEN duplicate_column THEN NULL;
END $$;

-- Index on ref for filtering by branch (idempotent)
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_ref ON webhook_deliveries(ref) WHERE ref IS NOT NULL;
