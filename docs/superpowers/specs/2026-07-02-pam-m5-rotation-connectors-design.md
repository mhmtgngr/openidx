# PAM M5 — Rotation connectors (SSH + PostgreSQL)

> Final milestone of the [PAM roadmap](2026-07-02-pam-architecture-roadmap.md). Adds two
> target-system `Rotator` connectors behind the M1b interface so the rotation engine can
> rotate credentials on **Linux/SSH hosts** and **PostgreSQL** databases — not just the
> directory. Scope: SSH + PostgreSQL (both use existing deps: `golang.org/x/crypto/ssh`,
> `pgx v5`). MySQL (needs a driver) and cloud IAM (heavy SDKs, not CI-verifiable) are
> deferred follow-ups.

## Context

M1b shipped the rotation engine with a `Rotator` interface
(`internal/credentials/rotator.go`) — `Type()`, `Apply(ctx, cfg, newValue)`,
`Verify(ctx, cfg, newValue)` — and two connectors (directory, generate-only), registered
in `cmd/admin-api/main.go`. M5 adds SSH and PostgreSQL connectors so a
`credential_rotation_policies` row with `connector_type='ssh'` or `'postgres'` rotates the
credential on the real target.

**Bootstrap credential = a vault secret (dog-fooding PAM):** to change a target's
credential you must first authenticate to the target with a privileged/admin credential.
That admin credential is itself stored in the vault; the connector resolves it via
`vault.Service.Use` at rotation time — never in plaintext config. So both connectors hold a
`*vault.Service` (like `directoryRotator` holds `*directory.Service`).

## Design

### Rotator interface (unchanged)
`Apply` receives only the **new** value; the connector obtains the **admin/bootstrap**
credential itself from the vault via `connector_config.admin_secret_id`. `Verify` confirms
the new credential works on the target; return `ErrVerifyUnsupported` to skip.

### SSH connector (`internal/credentials/ssh_rotator.go`)

- `Type() == "ssh"`. `NewSSHRotator(v *vault.Service) Rotator`.
- `connector_config`: `{host, port(=22), username (the target account to rotate),
  admin_secret_id (vault secret for a sudo-capable bootstrap account),
  admin_username, admin_auth ("password"|"private_key")}`.
- **Apply(newValue):**
  1. `admin, _ := vault.Use(bypassCtx, admin_secret_id)` (server-side; `defer zero`).
  2. Dial `host:port` via `x/crypto/ssh` as `admin_username` (password or private-key auth
     from `admin`), with a bounded timeout and a pinned/known-hosts-tolerant
     `HostKeyCallback` (configurable; default `ssh.InsecureIgnoreHostKey` is **not**
     acceptable — accept a `host_key` fingerprint in config, else fail).
  3. Run a non-interactive password set: `printf '%s:%s' <username> <newValue> | sudo
     chpasswd` (or `chpasswd` when the admin *is* root). The command is built with the
     username from config and the new value piped via stdin (never on the argv/command
     line, so it doesn't leak via `ps`); the connector writes `newValue` to the session's
     stdin.
  4. Non-zero exit → error (rotation fails; engine leaves current version).
- **Verify(newValue):** dial as `username` with `newValue`; success → nil; auth failure →
  error. (This is the strong signal the rotation worked.)
- Assumptions (documented): target is a POSIX host with `chpasswd` and the bootstrap
  account can `sudo` (or is root). SSH-key rotation is a future variant.

### PostgreSQL connector (`internal/credentials/postgres_rotator.go`)

- `Type() == "postgres"`. `NewPostgresRotator(v *vault.Service) Rotator`.
- `connector_config`: `{host, port(=5432), dbname, sslmode, admin_secret_id,
  admin_username, target_role}`.
- **Apply(newValue):**
  1. `admin, _ := vault.Use(bypassCtx, admin_secret_id)` (`defer zero`).
  2. `pgx.Connect` as `admin_username` (password=`admin`) to `host:port/dbname`
     (sslmode from config; timeout).
  3. Execute `ALTER ROLE <target_role> WITH PASSWORD $1` — **critical:** `ALTER ROLE`
     cannot parameterize the role name and PostgreSQL does not accept a bind param for the
     password in DDL, so the password must be inlined **safely**. Use
     `pgx.Identifier{target_role}.Sanitize()` for the role and Postgres string-literal
     escaping (or `quote_literal` via a `SELECT format('ALTER ROLE %I WITH PASSWORD %L',
     $1, $2)` executed then run) — do NOT naively concatenate. Preferred: run
     `SELECT format('ALTER ROLE %I WITH PASSWORD %L', $1, $2)` to get a safely-quoted DDL
     string server-side, then `Exec` it. (`%I` quotes the identifier, `%L` the literal.)
  4. Error → rotation fails.
- **Verify(newValue):** open a fresh `pgx.Connect` as `target_role` with `newValue`; ping;
  success → nil.

### Engine registration

`cmd/admin-api/main.go`: extend the `rotators` slice with
`credentials.NewSSHRotator(vaultSvc)` and `credentials.NewPostgresRotator(vaultSvc)`
(the `vaultSvc` already built there for M1). No engine changes — the map keys by `Type()`.
Also register in `cmd/access-service` / `cmd/governance-service` only if those run the
rotation scheduler (they don't — the scheduler runs in admin-api; confirm and register
only where `credentials.Service.StartScheduler` is invoked).

## Cross-cutting

- **Security:** admin + new credentials are `[]byte`, `defer zero`'d; never logged (no
  password in argv — SSH via stdin, Postgres via `%L` server-side quoting); `Use` runs
  under bypass; connector errors are logged without the secret. No plaintext in
  `connector_config` (only a `admin_secret_id` reference).
- **Host-key / TLS:** SSH requires a configured `host_key` (no blind
  `InsecureIgnoreHostKey`); Postgres honors `sslmode`.
- **No new dependencies** (x/crypto/ssh + pgx already vendored). No migration (reuses
  `credential_rotation_policies.connector_type` + `connector_config` JSONB from v57).
- **Verifiability:** the apply/verify against a real SSH host / Postgres can't run in CI —
  unit-test the pure builders (`buildChpasswdStdin`, the `ALTER ROLE` via `format`, config
  parsing/validation, host-key parsing) and the `Type()`/registration; the live path is a
  box/manual check. The connectors fail-closed (a rotation errors rather than silently
  succeeding) so a misconfig never promotes an unverified credential.

## Testing

- **Unit:** config validation (required fields per connector; reject missing
  admin_secret_id/target_role/host_key); the chpasswd stdin builder (`<user>:<newValue>`,
  no argv leak); the safe `ALTER ROLE` DDL construction (identifier/literal quoting; a role
  name with a quote/®; a password with quotes/backslashes is escaped); `Verify` returns
  `ErrVerifyUnsupported` never (both support verify); `Type()` strings.
- **Integration (optional, gated):** if a throwaway Postgres is reachable, an end-to-end
  Postgres rotation (seed an admin secret in the vault, a target role; rotate; verify the
  new password connects) — behind the existing integration build tag + DB availability
  skip. SSH e2e is manual (needs an sshd) — documented, not in CI.
- Gates: build, vet, gofmt, `orgscope -fail ./internal`, golangci-lint, govulncheck,
  `go test`.

## Verification (box)

Store an admin/bootstrap credential in the vault; create a `credential_rotation_policies`
row `connector_type='postgres'` (or `'ssh'`) with `connector_config` referencing it and the
target; trigger rotate-now → the target's password changes, `Verify` confirms it, the vault
promotes the new version, and the `credential_rotations` ledger shows `succeeded`.

## Out of scope
- MySQL (needs `go-sql-driver/mysql`), cloud IAM key rotation (AWS/GCP/Azure SDKs) — future
  connectors behind the same interface.
- SSH **key** rotation (this ships SSH **password** rotation); a key variant is a follow-up.
- Host-key discovery/TOFU UX (config supplies the pin).

## Critical files
- New: `internal/credentials/ssh_rotator.go`, `internal/credentials/postgres_rotator.go`,
  `internal/credentials/{ssh_rotator_test.go,postgres_rotator_test.go}`.
- Modify: `cmd/admin-api/main.go` (register the two rotators with `vaultSvc`).
- Reuse: `Rotator` interface + `ErrVerifyUnsupported` (`internal/credentials/rotator.go`),
  `vault.Service.Use` (`internal/vault/store.go`), the M1b engine/scheduler (unchanged),
  `credential_rotation_policies` (v57).
