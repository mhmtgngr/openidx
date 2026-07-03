-- 202607030002: Widen identity_providers.client_secret to TEXT for encryption at rest.
--
-- The external-IdP OIDC client secret is now stored AES-256-GCM-encrypted
-- (secretcrypt, tag "encv1:") instead of plaintext; base64 ciphertext exceeds
-- VARCHAR(255), so the column must be TEXT or INSERTs/UPDATEs would truncate the
-- ciphertext and the row could never decrypt. Mirrors internal/migrations v66 +
-- init-db.sql (the canonical schema sources).
ALTER TABLE identity_providers ALTER COLUMN client_secret TYPE TEXT;
