# Secret rotation

Where OpenIDX's secrets live, and how to rotate them safely — especially the
encryption master key.

## The two irreducible bootstrap secrets
A service needs these *before* it can read anything else; they can't live in the
store they unlock, so they stay in the `0600` env (`common.env` / `run-access.sh`):

- **`DATABASE_URL`** — locates the DB (where the vault + all secrets live).
- **The encryption KEK** — unlocks the encrypted-at-rest columns (see below).

Everything else *can* eventually move into the vault (roadmap: dogfood the PAM
vault for platform secrets — guac/ziti/apisix admin creds, internal token —
fetched at boot). That's a follow-up.

## Encryption-at-rest key — now rotatable (the `secretcrypt` keyring)

`secretcrypt` encrypts the sensitive columns (RS256 signing keys, TOTP/MFA
secrets, IdP client secrets, webhook secrets, per-user Guacamole passwords,
session recordings, …). It now supports a **KEK keyring** — the same
id-tagged model `internal/vault/crypto.go` already uses — so the master key
rotates **without a re-encryption flag-day**:

- `encv1:<b64>` — single-key, sealed under `ENCRYPTION_KEY` (the pre-keyring default; still read).
- `encv2:<kekID>:<b64>` — keyring, sealed under the KEK with that id.

**Single-key mode (default)** is unchanged: no `ENCRYPTION_KEYS` set → seals
`encv1`, byte-compatible with existing data. **Keyring mode is opt-in.**

### Env

| Var | Meaning |
|-----|---------|
| `ENCRYPTION_KEY` | 32-byte key. In keyring mode it's the reader for existing `encv1` values. |
| `ENCRYPTION_KEYS` | The ring: `"1:<base64-32B>,2:<base64-32B>"`. Presence switches on keyring mode. |
| `ENCRYPTION_ACTIVE_KEK_ID` | Which id new writes seal under. |

### Rotation procedure (safe, no downtime)

1. **Add** the current key to the ring and turn keyring mode on, active = current:
   - `ENCRYPTION_KEYS="1:<base64(current ENCRYPTION_KEY)>"`, `ENCRYPTION_ACTIVE_KEK_ID=1`, keep `ENCRYPTION_KEY`. Restart. (New writes become `encv2:1`; old `encv1` still read via `ENCRYPTION_KEY`.)
2. **Rotate**: add a new key and flip active:
   - `ENCRYPTION_KEYS="1:<old>,2:<new>"`, `ENCRYPTION_ACTIVE_KEK_ID=2`. Restart. New writes are `encv2:2`; everything sealed under key 1 (and `encv1`) still decrypts.
3. **Re-encrypt** (to retire the exposed key): run the re-encryption pass so all
   `encv1` / `encv2:1` values are re-sealed under key 2. *(Tool is the next step —
   see below.)*
4. **Retire**: drop key 1 from `ENCRYPTION_KEYS` (and eventually `ENCRYPTION_KEY`).
   Only safe once nothing is sealed under it — step 3 guarantees that.

Generate a key: `openssl rand -base64 32`.

## Rotating the other secrets
- **`INTERNAL_SERVICE_TOKEN`** — new value in `common.env` + `run-access.sh`, restart all services together.
- **`GUACAMOLE_ADMIN_PASSWORD`** — update the guac DB admin user + env, restart access-service.
- **`APISIX_ADMIN_KEY`** — update the APISIX config + the reconciler env, restart edge + access.
- **`ZITI_ADMIN_PASSWORD`** — update the controller admin + env, restart.
- **`JWT_SECRET`** — vestigial (only referenced in `doctor.go`; OAuth uses RS256 JWKS). Rotating it is a no-op; consider removing it.

## Status / next
- ✅ `secretcrypt` keyring (this change) — master-key rotation is now a safe config change.
- ⬜ **Re-encryption tool** (`cmd/`/`tools/`) — walk every encrypted column, decrypt with the ring, re-seal under the active KEK. Needed to fully retire an exposed key (step 3).
- ⬜ **Platform secrets → vault** — move the plaintext env secrets into the vault, fetch at boot, rotate via the rotation engine.
