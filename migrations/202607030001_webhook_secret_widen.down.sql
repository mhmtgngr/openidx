-- 202607030001 down (best-effort; fails if any secret now exceeds 255 chars).
ALTER TABLE webhook_subscriptions ALTER COLUMN secret TYPE VARCHAR(255);
