# Weak-sensitive-data-hashing remediation

**Goal:** Resolve the 5 `go/weak-sensitive-data-hashing` (high) alerts. One is a clear false positive
(already dismissed); the rest are real. Lead with the hardware-token secret (plaintext MFA seeds at
rest); backup-KDF is a follow-up (crypto-format versioning).

## Classification

| # | Location | What | Verdict |
|---|----------|------|---------|
| #174 | `identity/passwords.go:114` | `sha1` for **HaveIBeenPwned k-anonymity** (send first 5 hex chars, compare suffixes) | **FP — DISMISSED** (SHA-1 mandated by the HIBP API; breach-check, not storage; no secret persisted) |
| #275 | `identity/hardware_token.go:456` | `encryptSecret` = `hex(sha256(secret)) + ":" + secret` → stores the TOTP seed **recoverably** (plaintext after `:`) | **REAL — fix (this PR)** |
| #1011/1012 | `backup/backup.go:560/586` | AES key = raw `sha256(passphrase)` (no KDF work factor) | **REAL — follow-up (versioned scrypt)** |
| #1013 | `backup/backup.go:718` | `EncryptPassword` = salted single-round `sha256` | **REAL — follow-up (versioned scrypt)** |

## Design (this PR: hardware-token secret encryption)

`hardware_token.go` is in package `identity`; the `Service` already holds `idpCipher *secretcrypt.Cipher`
(AES-256-GCM, prefix-aware `encv1:`, KEK from `ENCRYPTION_KEY`/`VAULT_KEK`, `NewNoop()` fallback) used
for `identity_providers.client_secret`. Reuse it for the token secret.

- **`encryptSecret(secret)`** → `s.idpCipher.Encrypt(secret)` (returns `encv1:<ct>`; Noop passes through
  in dev). Replaces the fake `hex(sha256)+":"+secret`.
- **`decryptSecret(stored)`** — handle both new and legacy values:
  ```go
  func (s *Service) decryptSecret(stored string) string {
      if secretcrypt.IsEncrypted(stored) {          // encv1: → real decrypt
          if v, err := s.idpCipher.Decrypt(stored); err == nil {
              return v
          }
          return ""
      }
      // Legacy format written before this fix: "<64-hex-sha256>:<secret>". Strip the hash prefix.
      if i := strings.IndexByte(stored, ':'); i == 64 && isHex(stored[:i]) {
          return stored[i+1:]
      }
      return stored // plaintext/unknown — return as-is
  }
  ```
- **Migration:** existing rows stay readable (legacy branch); they upgrade to `encv1:` the next time the
  secret is re-written (enrollment/rotation). No data migration required. (Optionally note that a one-off
  re-encrypt backfill could be added later; not needed for correctness.)
- Clears `go/weak-sensitive-data-hashing` #275 (the SHA-256-of-secret is gone) and, more importantly,
  stops storing MFA seeds recoverably at rest.

Rename note: `idpCipher` is now used for two secret kinds — acceptable (same KEK/cipher). Leave the field
name or rename to `secretCipher` at the implementer's discretion (cosmetic; keep the diff focused).

## Testing / verification
- `TestEncryptDecryptSecret_RoundTrip`: with a real cipher (`secretcrypt.New(testKey)`), `encryptSecret`
  output is `encv1:`-prefixed (not the plaintext), and `decryptSecret` round-trips to the original.
- `TestDecryptSecret_LegacyFormat`: a legacy `"<64hex>:mysecret"` value → `decryptSecret` returns
  `mysecret` (back-compat). A bare plaintext → returned as-is.
- `go build ./... && go vet ./internal/identity/ && gofmt -l && go test ./internal/identity/` clean;
  `golangci-lint run ./internal/identity/` clean.
- Post-PR: `go/weak-sensitive-data-hashing` #275 clears on the merge-ref.
- Box-relevant (identity service) → deploy after merge; the box's `ENCRYPTION_KEY` backs the cipher, so
  new hardware-token secrets are AES-GCM at rest.

## Scope / risk
- `internal/identity/hardware_token.go` (+ test). No schema change (the column stays TEXT; format goes
  from `hash:secret` to `encv1:ct`). Legacy rows readable via the shim; upgrade on next write.
- **Follow-up (separate PR):** backup-KDF ×3 — switch the passphrase→key derivation to `scrypt`
  (`golang.org/x/crypto/scrypt`) with a **version byte + random salt prepended** to the ciphertext, and a
  `decrypt` that reads the version (scrypt for new, legacy raw-`sha256` fallback for existing backups) so
  old encrypted backups remain decryptable. Design decision to confirm at that PR: legacy-fallback vs
  hard cut-over (fallback recommended).
