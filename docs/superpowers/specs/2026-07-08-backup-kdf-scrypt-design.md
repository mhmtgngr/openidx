# Backup encryption KDF: scrypt + delete dead EncryptPassword

**Goal:** Resolve the last 3 `go/weak-sensitive-data-hashing` (high) alerts in `internal/backup/backup.go`.

## Classification
- **`EncryptPassword` (#1013, :718)** — `salt + sha256(salt||password)`, "encrypts a password for
  config files". **Zero callers repo-wide → dead code. DELETE it** (removes the alert + dead crypto;
  no compat concern). `encoding/base64` (its only user) drops with it.
- **`encrypt`/`decrypt` (#1011/#1012, :560/:586)** — derive the AES-256 backup key as a raw
  `sha256(passphrase)` (no KDF work factor → brute-forceable for a low-entropy passphrase). Used when
  `Manager.config.EncryptionKey != ""`. **Real weak-KDF.**

## Design (encrypt/decrypt → scrypt, versioned + back-compatible)
Derive the key with `scrypt` (`golang.org/x/crypto/scrypt`, N=1<<15, r=8, p=1, 32B) over a random
per-backup salt. New ciphertext format: `MAGIC(8) || salt(16) || nonce || sealed`, where
`MAGIC = "OIDXbk2\x00"`. `decrypt` detects the magic:
- **new** → strip magic, read salt, `scrypt(passphrase, salt)`, then GCM-open `nonce||sealed`.
- **legacy** (no magic; existing backups) → `sha256(passphrase)` key, `nonce = data[:12]` — so old
  encrypted backups still decrypt. (Legacy nonce is a random 12 bytes; P(it starts with the 8-byte MAGIC)
  ≈ 2^-64 → unambiguous.)
Add `deriveBackupKey(passphrase string, salt []byte) ([]byte, error)`.

## Testing
- `TestBackupEncryptRoundTrip`: `encrypt`(new scrypt format) → output starts with MAGIC, not the
  plaintext → `decrypt` round-trips.
- `TestBackupDecryptLegacy`: hand-build a legacy blob (`nonce || gcm.Seal` with `sha256(passphrase)` key)
  → `decrypt` reads it (back-compat).
- `TestBackupDecryptWrongPassphrase`: decrypt with a different passphrase → error.
- `go build/vet/gofmt/golangci-lint/go test ./internal/backup/` clean; #1011/1012/1013 clear on merge-ref.

## Scope
`internal/backup/backup.go` (+ test). Back-compatible (legacy decrypt retained). No migration. Box: this
Manager isn't the pg_dump path, but the fix is real; deploy rides the batched release.
