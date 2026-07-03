-- 202607030002 down (best-effort; fails if any secret now exceeds 255 chars).
ALTER TABLE identity_providers ALTER COLUMN client_secret TYPE VARCHAR(255);
