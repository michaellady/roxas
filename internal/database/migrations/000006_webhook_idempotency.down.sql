-- Revert idempotency columns from webhook_deliveries
DROP INDEX IF EXISTS idx_webhook_deliveries_ref;
DROP INDEX IF EXISTS idx_webhook_deliveries_delivery_id;
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS after_sha;
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS before_sha;
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS ref;
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS delivery_id;
