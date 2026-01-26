-- Revert webhook delivery idempotency columns (alice-77)
DROP INDEX IF EXISTS idx_webhook_deliveries_ref;
DROP INDEX IF EXISTS idx_webhook_deliveries_idempotency;

ALTER TABLE webhook_deliveries
    DROP COLUMN IF EXISTS after_sha,
    DROP COLUMN IF EXISTS before_sha,
    DROP COLUMN IF EXISTS ref,
    DROP COLUMN IF EXISTS delivery_id;
