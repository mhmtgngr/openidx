package migrations

// Migration v65 — widen webhook_subscriptions.secret to TEXT for encryption at
// rest. The HMAC signing secret is now stored AES-256-GCM-encrypted (secretcrypt,
// tagged "encv1:") instead of plaintext; the base64 ciphertext exceeds VARCHAR(255),
// so the column must be TEXT. Encryption itself is applied by the webhooks service
// on write + decrypted on read (prefix-aware, so legacy plaintext rows still read
// and sign correctly); UpdateSubscription does not rewrite the secret, so existing
// plaintext rows are migrated by a one-off backfill tool at deploy time.
// Idempotent (ALTER ... TYPE TEXT is a no-op when already TEXT). init-db.sql defines
// the column as TEXT directly, so TestInitDB(Column)Parity is unaffected.
var webhookSecretWidenUp = `-- Migration 065: widen webhook_subscriptions.secret to TEXT for encryption at rest.
ALTER TABLE webhook_subscriptions ALTER COLUMN secret TYPE TEXT;
`

var webhookSecretWidenDown = `-- Migration 065 down (best-effort; fails if any secret now exceeds 255 chars).
ALTER TABLE webhook_subscriptions ALTER COLUMN secret TYPE VARCHAR(255);
`
