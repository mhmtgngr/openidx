-- 202607030001: Widen webhook_subscriptions.secret to TEXT for encryption at rest.
--
-- The HMAC signing secret is now stored AES-256-GCM-encrypted (secretcrypt, tag
-- "encv1:") instead of plaintext; the base64 ciphertext exceeds VARCHAR(255), so
-- the column must be TEXT or INSERTs would truncate the ciphertext and the row
-- could never decrypt. Mirrors internal/migrations v65 + init-db.sql (the
-- canonical schema sources); this keeps the file-based migration path consistent.
ALTER TABLE webhook_subscriptions ALTER COLUMN secret TYPE TEXT;
