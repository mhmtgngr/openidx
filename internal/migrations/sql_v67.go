package migrations

// Migration v67 — widen guacamole_connection_pool.token to TEXT for encryption at
// rest. The pooled Guacamole session token is now stored AES-256-GCM-encrypted
// (secretcrypt, tag "encv1:") instead of plaintext; base64 ciphertext of a
// VARCHAR(500) token exceeds 500 chars. The token column is WRITE-ONLY (the
// in-memory pool serves reads; nothing SELECTs it back), so the access service
// only encrypts on write — a DB dump can't yield usable session tokens. Idempotent;
// init-db.sql defines the column as TEXT directly. Not in the file-based migrations/
// set (guacamole_connection_pool was reconciled by v54, init-db-only originally).
var guacTokenWidenUp = `-- Migration 067: widen guacamole_connection_pool.token to TEXT for encryption at rest.
ALTER TABLE guacamole_connection_pool ALTER COLUMN token TYPE TEXT;
`

var guacTokenWidenDown = `-- Migration 067 down (best-effort; fails if any token now exceeds 500 chars).
ALTER TABLE guacamole_connection_pool ALTER COLUMN token TYPE VARCHAR(500);
`
