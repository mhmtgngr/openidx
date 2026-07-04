# Rotation connectors: MySQL + SSH key-pair

**Goal:** Extend the PAM credential-rotation engine (M5) with two new `Rotator` connectors —
**MySQL** user-password rotation and **SSH key-pair** rotation — behind the existing interface.
Cloud-IAM (AWS/GCP) is **explicitly deferred** (heavy SDKs, not locally verifiable).

**Verified current state (2026-07-04):**
- `internal/credentials/rotator.go` — `type Rotator interface { Type() string; Apply(ctx, cfg map[string]any, newValue []byte) error; Verify(ctx, cfg, newValue) error }`. `generateSecret(gp GenerationPolicy)` makes a random password.
- Connectors today: `generate_only`, `directory`, `ssh` (POSIX **password** via `chpasswd`), `postgres` (ALTER ROLE). Registered as a `[]Rotator` slice in `cmd/admin-api/main.go:296`.
- `vaultUser` seam: `Use(ctx, secretID) ([]byte, error)` (satisfied by `*vault.Service`) resolves the bootstrap **admin** credential from the vault. Connectors call `orgctx.WithBypassRLS(ctx)` before `Use`.
- **Engine flow** (`engine.go:83 runRotation`): `newValue = generateSecret(gp)` → `AddCandidateVersion(secretID, newValue)` → `Apply(cfg, newValue)` → `Verify(cfg, newValue)` → promote. **No per-connector value generator.**
- Drivers: `golang.org/x/crypto` present (has `ssh` + `ed25519` keygen). **No** `go-sql-driver/mysql` (new dep for MySQL). No AWS/GCP SDK (cloud deferred).
- Security patterns to preserve: admin secret `defer zero()`'d; DSNs/keys never logged; SSH uses `ssh.FixedHostKey` from a required `host_key` (never `InsecureIgnoreHostKey`); secrets never on the command line.

---

## PR 1 — Engine `ValueGenerator` seam + SSH key-pair connector (no new deps)

### Engine change — optional value generator
A key rotation's stored value must be a **private key**, not a password. Add an optional interface
in `rotator.go`:
```go
// ValueGenerator lets a connector produce the secret value itself (e.g. an SSH private key)
// instead of the engine's default random-password generateSecret. Optional — connectors that
// don't implement it keep using generateSecret.
type ValueGenerator interface {
	Generate(gp GenerationPolicy) ([]byte, error)
}
```
In `runRotation` (`engine.go:84`), replace `newValue, err := generateSecret(gp)` with:
```go
	var newValue []byte
	var err error
	if g, ok := r.(ValueGenerator); ok {
		newValue, err = g.Generate(gp)
	} else {
		newValue, err = generateSecret(gp)
	}
```
Everything downstream (AddCandidateVersion/Apply/Verify/promote/`defer zero`) is unchanged — the
value is still an opaque `[]byte` stored in the vault and retrievable at checkout.

### `ssh_key_rotator.go` — `Type() == "ssh_key"`
- Implements `Rotator` **and** `ValueGenerator`. Struct `{ vault vaultUser }`; `NewSSHKeyRotator(v)`.
- **Generate(gp):** create an **ed25519** keypair; return the **OpenSSH-format private key PEM** as the
  value (`ssh.MarshalPrivateKey` → `pem.EncodeToMemory`). (gp is ignored for keys — key type is fixed
  ed25519; note this in a comment.) The public key is derived from the private key in Apply/Verify, so
  only the private key needs storing.
- **cfg** (parsed like `sshConf`, reuse `sshConfigFromMap` where possible): `host`, `port` (22),
  `username` (target account), `admin_secret_id`, `admin_username`, `admin_auth` (password|private_key),
  `host_key` (required, `FixedHostKey`). No `target`-password fields.
- **Apply(cfg, newValue):** parse the private key from `newValue` → derive the public key
  (`authorized_keys` line) tagged with a fixed comment `openidx-rotated:<username>`. Dial as admin
  (reuse the existing `dial`/`fixedHostKey` helpers), then **rewrite the target's
  `~<username>/.ssh/authorized_keys` replacing the single line carrying that tag** (idempotent — keys
  never accumulate; other keys preserved). Do this with a small, quoted remote script fed via stdin
  (grep -v the tag, append the new line, write atomically to a temp file, `mv`), `sudo`-prefixed when
  the admin isn't root (mirror `chpasswdCommand`). The public key line is safe to place in the script
  (it's not secret); the **private key never leaves the vault/engine**.
- **Verify(cfg, newValue):** parse the private key → `ssh.PublicKeys(signer)` → dial AS `username` with
  that key (reuse `dialAs`). Success proves the new key is installed.
- Unit tests (`ssh_key_rotator_test.go`): Generate produces a parseable ed25519 OpenSSH private key;
  the derived authorized_keys line round-trips; cfg validation mirrors ssh. (The remote-apply path is
  covered by the live smoke.)

### Register + verify
- `cmd/admin-api/main.go:296` rotators slice: add `credentials.NewSSHKeyRotator(vaultSvc)`.
- **Live smoke (throwaway sshd container):** create a policy of type `ssh_key`, rotate, and confirm an
  SSH login AS the target using the rotated private key succeeds; re-rotate and confirm authorized_keys
  still has exactly one managed line. (Details in the plan; uses a `linuxserver/openssh-server` or
  `rastasheep/ubuntu-sshd`-style throwaway.)

---

## PR 2 — MySQL connector (new dep `go-sql-driver/mysql`)

### `mysql_rotator.go` — `Type() == "mysql"` (mirror `postgres_rotator.go`)
- Struct `{ vault vaultUser }`; `NewMySQLRotator(v)`.
- **cfg** (`mysqlConfigFromMap`, mirror `pgConfigFromMap`): `host`, `port` (3306), `admin_secret_id`,
  `admin_username`, `target_user`, `target_host` (default `%`), optional `dbname`, optional `tls`.
- **Apply:** resolve admin → open `database/sql` with the `mysql` driver as admin →
  `ALTER USER <target_user>@<target_host> IDENTIFIED BY '<newValue>'`.
  **⚠️ SECURITY — the load-bearing concern:** MySQL cannot bind the password as a `?` parameter in
  `ALTER USER` (it's DDL), and has no server-side `format(%L)` like Postgres. So:
  - Quote the **identifier** parts (`target_user`/`target_host`) by validating them against a strict
    charset (reject anything outside `[A-Za-z0-9_.%-]`) — do NOT accept arbitrary identifiers.
  - Escape the **password** as a MySQL single-quoted string literal: `\` → `\\`, `'` → `\'`, and reject
    embedded NUL. Guard the session mode first: `SET SESSION sql_mode = REPLACE(@@sql_mode,'NO_BACKSLASH_ESCAPES','')`
    (or read `@@sql_mode` and **fail** if `NO_BACKSLASH_ESCAPES` is set, since it would change escaping
    semantics). Document this precisely; it is the #1 review item.
  - Never log the DSN or the DDL string.
- **Verify:** open a new connection AS `target_user`@… with `newValue` → `PingContext`. Success proves
  the rotation applied.
- Unit tests (`mysql_rotator_test.go`): `mysqlConfigFromMap` validation; the password escaper
  (`'`, `\`, combos, NUL-reject); identifier validation rejects injection attempts. (Live apply covered
  by smoke.)

### Register + verify
- `cmd/admin-api/main.go`: add `credentials.NewMySQLRotator(vaultSvc)` to the rotators slice.
- `go mod tidy` to add `github.com/go-sql-driver/mysql`.
- **Live smoke (throwaway `mysql:8` container):** seed a target user, run a rotation, confirm the target
  user can log in with the new password and the old one is rejected. (Details in the plan.)

---

## Sequencing & scope
- **PR 1 (engine seam + ssh_key)** first — no new deps; the engine change is tiny and additive.
- **PR 2 (mysql)** second — carries the new dependency + the escaping-security surface (heaviest review).
- Each: adversarial review (PR2's escaping gets a hard look) + CI green + per-PR merge go-ahead.
- These are **app-layer** (new code + one dep); a box deploy is optional/provenance — the box's PAM
  rotation is exercised only if policies of these types exist. Decide deploy per your call after release.
- The registration list changing means `cmd/admin-api` — confirm no `main_test.go` fixture asserts the
  exact rotator set/count; update if so.

## Out of scope (deferred to a later initiative)
- **cloud-IAM (AWS access keys / GCP SA keys)** — heavy SDK deps, two providers, not locally verifiable.
- Key types other than ed25519 for ssh_key; MySQL auth plugins beyond the default (`caching_sha2_password`
  via `IDENTIFIED BY` works; `IDENTIFIED WITH … AS '<hash>'` is a follow-up).
- Rotating the admin bootstrap credential itself.

## Open questions (resolve at implementation)
1. **MySQL sql_mode handling:** set-session-mode vs fail-on-NO_BACKSLASH_ESCAPES — pick the safer;
   confirm the default MySQL 8 image doesn't set it.
2. **authorized_keys rewrite atomicity** under concurrent rotations — the managed-line-by-tag rewrite +
   temp-file `mv` should be atomic per host; confirm no interleaving hazard for a single target.
3. **ssh_key on a target with no `~/.ssh`** — Apply must `mkdir -p ~/.ssh && chmod 700` first.
