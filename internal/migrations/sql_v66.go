package migrations

// Migration v66 — widen identity_providers.client_secret to TEXT for encryption
// at rest. The external-IdP OIDC client secret (used for outbound token exchange)
// is now stored AES-256-GCM-encrypted (secretcrypt, tag "encv1:") instead of
// plaintext; base64 ciphertext exceeds VARCHAR(255). The identity service
// encrypts on create/update and decrypts on read; the access service (multi_idp)
// decrypts on its direct reads; oauth reads via identity.GetIdentityProvider (also
// decrypted). Reads are prefix-aware so legacy plaintext rows still work and
// re-encrypt on the next Update; any never-updated rows can be migrated by
// re-saving the IdP (or a throwaway backfill) at deploy time.
// Idempotent; init-db.sql defines the column as TEXT directly.
var idpClientSecretWidenUp = `-- Migration 066: widen identity_providers.client_secret to TEXT for encryption at rest.
ALTER TABLE identity_providers ALTER COLUMN client_secret TYPE TEXT;
`

var idpClientSecretWidenDown = `-- Migration 066 down (best-effort; fails if any secret now exceeds 255 chars).
ALTER TABLE identity_providers ALTER COLUMN client_secret TYPE VARCHAR(255);
`
